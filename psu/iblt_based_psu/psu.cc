#include "examples/upsi/psu/iblt_based_psu/psu.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/MultiKeyAES.h"
#include "examples/upsi/psu/iblt_based_psu/volePSI/RsOprf.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/BitIterator.h"

#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"
#include "libOTe/Tools/RepetitionCode.h"

#include <thread>
#include <vector>
#include <random>
#include <span>
#include <string>
#include <cstdlib>
#include <iostream>
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

using psu::Sender;
using psu::Receiver;
using psu::Item;
using psu::ItemSet;
using psu::ItemVec;
using psu::MaskedMsg;
using volePSI::RsOprfSender;
using volePSI::RsOprfReceiver;
using std::vector;
using std::array;
using coproto::Socket;
using volePSI::Proto;
using namespace osuCrypto;

static constexpr size_t IBLT_NUM_HASH_FUNCS = 5;

static bool PsuDebugEnabled() {
    const char* env = std::getenv("IBLT_PSU_DEBUG");
    if (env == nullptr) {
        return false;
    }
    return std::string(env) != "0";
}

static void PsuDebugLog(const char* side, const std::string& msg) {
    if (!PsuDebugEnabled()) {
        return;
    }
    std::cerr << "[iblt_psu][" << side << "] " << msg << std::endl;
}

static bool PsuMultiKeyAesEnabled() {
    const char* env = std::getenv("IBLT_PSU_MULTIKEY_AES");
    if (env == nullptr) {
        return false;
    }
    return std::string(env) != "0";
}

template <typename ProbeFn>
static void FillUvFromEvalOutputs(Sender& sender,
                                  uint64_t round_num,
                                  size_t count,
                                  ProbeFn&& probe_fn,
                                  const block* oprf_out_arr,
                                  const block* prng_out,
                                  AlignedUnVector<block>& uv) {
    auto& uv_use_oprf = sender.uv_use_oprf_scratch;
    auto& uv_slot = sender.uv_slot_scratch;

    if (!PsuMultiKeyAesEnabled()) {
        #pragma omp parallel if (count > 4096)
        {
            AES aes;
            #pragma omp for
            for (size_t i = 0; i < count; ++i) {
                if (uv_use_oprf[i]) {
                    aes.setKey(oprf_out_arr[uv_slot[i]]);
                    uv[i] = aes.ecbEncBlock(block(round_num, probe_fn(i)));
                } else {
                    uv[i] = prng_out[uv_slot[i]];
                }
            }
        }
        return;
    }

    auto& oprf_pos = sender.uv_oprf_pos_scratch;
    oprf_pos.clear();
    oprf_pos.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        if (uv_use_oprf[i]) {
            oprf_pos.push_back(i);
        } else {
            uv[i] = prng_out[uv_slot[i]];
        }
    }

    constexpr size_t kBatchSize = 8;
    const size_t batch_end = oprf_pos.size() / kBatchSize * kBatchSize;

    #pragma omp parallel if (oprf_pos.size() > 4096)
    {
        MultiKeyAES<kBatchSize> mk_aes;
        AES aes;
        std::array<block, kBatchSize> keys;
        std::array<block, kBatchSize> pts;
        std::array<block, kBatchSize> out;

        #pragma omp for schedule(static)
        for (size_t base = 0; base < batch_end; base += kBatchSize) {
            for (size_t j = 0; j < kBatchSize; ++j) {
                const size_t pos = oprf_pos[base + j];
                keys[j] = oprf_out_arr[uv_slot[pos]];
                pts[j] = block(round_num, probe_fn(pos));
            }
            mk_aes.setKeys(span<block>(keys.data(), kBatchSize));
            mk_aes.ecbEncNBlocks(pts.data(), out.data());
            for (size_t j = 0; j < kBatchSize; ++j) {
                uv[oprf_pos[base + j]] = out[j];
            }
        }

        #pragma omp for schedule(static)
        for (size_t i = batch_end; i < oprf_pos.size(); ++i) {
            const size_t pos = oprf_pos[i];
            aes.setKey(oprf_out_arr[uv_slot[pos]]);
            uv[pos] = aes.ecbEncBlock(block(round_num, probe_fn(pos)));
        }
    }
}

static coproto::task<void> setup_sender_eq_seeds(Socket& sock, 
                                                 Sender& sender) {
    MC_BEGIN(Proto, &sock, &sender,
             vals = (vector<block>*) nullptr,
             evalOut = (vector<block>*) nullptr,
             n_sndr_qs = size_t(0),
             threshold = size_t(0),
             otRecvr = (SoftSpokenShOtReceiver<>*) nullptr);
        otRecvr = new SoftSpokenShOtReceiver<>();
        otRecvr->init(sender.softspoken_ot_field_size, true);
        sender.oprfSender = new RsOprfSender();
        vals = new vector<block>();
        evalOut = new vector<block>();
        
        sender.baseSend.resize(otRecvr->baseOtCount());

        PsuDebugLog("sender", "setup:eq_seeds oprf send start");
        MC_AWAIT(sender.oprfSender->send(sender.recvr_set_size + otRecvr->baseOtCount(), sender.prng, sock, 0, sender.oprf_reduced_rounds));
        PsuDebugLog("sender", "setup:eq_seeds oprf send done");

        n_sndr_qs = 2*otRecvr->baseOtCount();

        vals->resize(n_sndr_qs);
        evalOut->resize(n_sndr_qs);

        for (size_t i = 0; i < n_sndr_qs; i = i + 2) {
            (*vals)[i] = block(1, i/2);
            (*vals)[i+1] = block(2, i/2);
        }

        sender.oprfSender->eval(*vals, *evalOut);

        for (size_t i = 0; i < n_sndr_qs; i = i + 2) {
            sender.baseSend[i/2][0] = (*evalOut)[i];
            sender.baseSend[i/2][1] = (*evalOut)[i+1];
        }

        threshold = sender.recvr_set_size + sender.sndr_set_size;

        sender.iblt = new iblt_5h(sender.iblt_seed, threshold, sender.iblt_mult_fac);
        sender.iblt->addKeys(*(sender.set_items));

        delete vals;
        delete evalOut;
        delete otRecvr;

    MC_END();
}

static coproto::task<void> setup_recvr_eq_seeds(Socket& sock, 
                                                Receiver& recvr) {
    MC_BEGIN(Proto, &sock, &recvr,
             oprfRecvr = (RsOprfReceiver*) nullptr,
             vals = (vector<block>*) nullptr,
             recvOut = (vector<block>*) nullptr,
             eq_seed_span = std::span<block>(),
             threshold = size_t(0),
             i = size_t(0),
             otSender = (SoftSpokenShOtSender<>*) nullptr);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(recvr.softspoken_ot_field_size, true);
        oprfRecvr = new RsOprfReceiver();
        vals = new vector<block>();
        recvOut = new vector<block>();


        recvr.baseChoices.resize(otSender->baseOtCount()); 
        recvr.baseRecv.resize(otSender->baseOtCount());

        recvr.baseChoices.randomize(recvr.prng);
        vals->resize(recvr.set_items->size() + otSender->baseOtCount());
        recvOut->resize(recvr.set_items->size() + otSender->baseOtCount());

        i=0;
        for (const auto& set_item : *(recvr.set_items)) {
            (*vals)[i] = set_item;
            ++i;
        }

        /*for (size_t i = 0; i < recvr.set_items->size(); ++i) {
            (*vals)[i] = block(0, recvr.set_items[i]);
        }*/
        for (size_t i = 0; i < otSender->baseOtCount(); ++i) {
            if(recvr.baseChoices[i] == true) {
                (*vals)[i+recvr.set_items->size()] = block(2, i);
            } else {
                (*vals)[i+recvr.set_items->size()] = block(1, i);
            }
        }

        PsuDebugLog("receiver", "setup:eq_seeds oprf recv start");
        MC_AWAIT(oprfRecvr->receive(*vals, *recvOut, recvr.prng, sock, 0, recvr.oprf_reduced_rounds));
        PsuDebugLog("receiver", "setup:eq_seeds oprf recv done");

        eq_seed_span = std::span<block>(recvOut->data(), recvr.set_items->size());

        threshold = recvr.recvr_set_size + recvr.sndr_set_size;

        recvr.iblt = new iblt_5h(recvr.iblt_seed, threshold, recvr.iblt_mult_fac);
        recvr.iblt->add(*(recvr.set_items), eq_seed_span);

        for (size_t i = 0; i < otSender->baseOtCount(); ++i) {
            recvr.baseRecv[i] = (*recvOut)[i + recvr.set_items->size()];
        }

        delete oprfRecvr;
        delete vals;
        delete recvOut;
        delete otSender;

    MC_END();
}

/*static size_t max_n_bin_probes(iblt_5h& iblt, size_t sender_set_size, size_t recvr_set_size) {
    size_t num_iblt_hash_funcs = iblt.NUM_HASH_FUNCS;
    size_t iblt_tab_len = iblt.tab_len;
    size_t max_union_set_size = sender_set_size + recvr_set_size;

    return iblt_tab_len + max_union_set_size*(num_iblt_hash_funcs);
}

static size_t max_n_bin_probes_per_round(iblt_5h& iblt) {
    return iblt.tab_len;
}
    */

static coproto::task<void> setup_receiver_ots_correlations(Socket& sock, 
                                                         Receiver& receiver,
                                                         iblt_5h& sender_iblt,
                                                         size_t sender_set_size, 
                                                         size_t recvr_set_size,
                                                         AlignedVector<block>& baseRecv,
                                                         BitVector& baseChoice) {
    MC_BEGIN(Proto, &sock, &receiver, &sender_iblt, &baseRecv, &baseChoice, sender_set_size, recvr_set_size,
             numOts = size_t(0),
             max_num_bin_probes = size_t(0),
             baseSend = span<std::array<block, 2>>(),
             otReceiver = (SoftSpokenShOtReceiver<>*) nullptr,
             otSender = (SoftSpokenShOtSender<>*) nullptr);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(receiver.softspoken_ot_field_size, true);
        otReceiver = new SoftSpokenShOtReceiver<>();
        otReceiver->init(receiver.softspoken_ot_field_size, true);

        max_num_bin_probes = psu::max_num_bin_probes(sender_iblt.tab_len, iblt_5h::NUM_HASH_FUNCS, sender_set_size, recvr_set_size);
        numOts = max_num_bin_probes;
        receiver.otCorrSendMsgs->resize(numOts + otSender->baseOtCount());

        otSender->setBaseOts(baseRecv, baseChoice);

        PsuDebugLog("receiver", "setup:ot_corr sender.send start");
        MC_AWAIT(otSender->send((*receiver.otCorrSendMsgs), receiver.prng, sock));
        PsuDebugLog("receiver", "setup:ot_corr sender.send done");

        baseSend = receiver.otCorrSendMsgs->subspan(numOts, otReceiver->baseOtCount());

        otReceiver->setBaseOts(baseSend);

        numOts = max_num_bin_probes*2;
        receiver.otCorrRecvChoices->resize(numOts);
        receiver.otCorrRecvMsgs->resize(numOts);

        receiver.otCorrRecvChoices->randomize(receiver.prng);
        PsuDebugLog("receiver", "setup:ot_corr receiver.receive start");
        MC_AWAIT(otReceiver->receive(*(receiver.otCorrRecvChoices), *(receiver.otCorrRecvMsgs), receiver.prng, sock));
        PsuDebugLog("receiver", "setup:ot_corr receiver.receive done");

        delete otReceiver;
        delete otSender;

    MC_END();
}

static coproto::task<void> setup_sender_ots_correlations(Socket& sock, 
                                                        Sender& sender,
                                                        iblt_5h& recvr_iblt,
                                                        size_t sender_set_size, 
                                                        size_t recvr_set_size,
                                                        AlignedVector<std::array<block, 2>>& baseSend) {
    MC_BEGIN(Proto, &sock, &sender, &baseSend, &recvr_iblt, sender_set_size, recvr_set_size,
             numOts = size_t(0),
             max_num_bin_probes = size_t(0),
             baseChoices = (BitVector*) nullptr,
             baseRecvMsgsSubspan = span<block>(),
             otSender = (SoftSpokenShOtSender<>*) nullptr,
             otRecvr = (SoftSpokenShOtReceiver<>*) nullptr);
        otRecvr = new SoftSpokenShOtReceiver<>();
        otRecvr->init(sender.softspoken_ot_field_size, true);
        otSender = new SoftSpokenShOtSender<>();
        otSender->init(sender.softspoken_ot_field_size, true);

        otRecvr->setBaseOts(baseSend);

        max_num_bin_probes = psu::max_num_bin_probes(recvr_iblt.tab_len, iblt_5h::NUM_HASH_FUNCS, sender_set_size, recvr_set_size);
        numOts = max_num_bin_probes;
        sender.otCorrRecvChoices->resize(numOts + otSender->baseOtCount());
        sender.otCorrRecvMsgs->resize(numOts + otSender->baseOtCount());
        sender.otCorrSendMsgs->resize(2 * numOts);

        sender.otCorrRecvChoices->randomize(sender.prng);

        PsuDebugLog("sender", "setup:ot_corr receiver.receive start");
        MC_AWAIT(otRecvr->receive(*(sender.otCorrRecvChoices), *(sender.otCorrRecvMsgs), sender.prng, sock));
        PsuDebugLog("sender", "setup:ot_corr receiver.receive done");

        baseChoices = new BitVector(otSender->baseOtCount());
        for (size_t i = 0; i < otSender->baseOtCount(); ++i) {
            (*baseChoices)[i] = (*(sender.otCorrRecvChoices))[numOts + i];
        }

        sender.otCorrRecvChoices->resize(numOts);

        baseRecvMsgsSubspan = sender.otCorrRecvMsgs->subspan(numOts, otSender->baseOtCount());

        otSender->setBaseOts(baseRecvMsgsSubspan, *baseChoices);

        numOts = max_num_bin_probes*2;

        PsuDebugLog("sender", "setup:ot_corr sender.send start");
        MC_AWAIT(otSender->send(*(sender.otCorrSendMsgs), sender.prng, sock));
        PsuDebugLog("sender", "setup:ot_corr sender.send done");

        delete otRecvr;
        delete otSender;
        delete baseChoices;
      
    MC_END();
}

coproto::task<void> psu::Sender::setup(Socket& sock, ItemSet& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0),
             iblt_tab_len = size_t(0));
       
        this->set_items = &set_items;
        PsuDebugLog("sender", "setup begin");

        if (this->oprfSender != nullptr) {
            delete this->oprfSender;
            this->oprfSender = nullptr;
        }
        if (this->rMaskedMsgs != nullptr) {
            delete this->rMaskedMsgs;
            this->rMaskedMsgs = nullptr;
        }
        if (this->iblt != nullptr) {
            delete this->iblt;
            this->iblt = nullptr;
        }
        this->consumed_recv_ots = 0;
        this->consumed_send_ots = 0;
        this->curr_round = 0;
        this->num_peel_iterations = 0;
        this->round_sender_owned_pld_els.clear();
        this->iblt_remove_unique_hash_evals.clear();
        iblt_tab_len = iblt_5h::calc_tab_len(this->recvr_set_size + this->sndr_set_size, this->iblt_mult_fac);
        this->peeled_bm.reset(iblt_tab_len);
        
        t0 = std::chrono::high_resolution_clock::now();

        PsuDebugLog("sender", "setup:eq_seeds start");
        MC_AWAIT(setup_sender_eq_seeds(sock, *this));
        PsuDebugLog("sender", "setup:eq_seeds done");

        PsuDebugLog("sender", "setup:ot_corr start");
        MC_AWAIT(setup_sender_ots_correlations(sock, *this, *(this->iblt), this->set_items->size(), this->recvr_set_size, this->baseSend));
        PsuDebugLog("sender", "setup:ot_corr done");

        this->rMaskedMsgs = new AlignedVector<MaskedMsg>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        PsuDebugLog("sender", "setup done, ms=" + std::to_string(duration));

    MC_END();
}

coproto::task<void> psu::Sender::wan_setup(Socket& sock, ItemSet& set_items) {
    
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
       
        this->set_items = &set_items;
        
        t0 = std::chrono::high_resolution_clock::now();

        MC_AWAIT(setup_sender_eq_seeds(sock, *this));

        MC_AWAIT(setup_sender_ots_correlations(sock, *this, *(this->iblt), this->set_items->size(), this->recvr_set_size, this->baseSend));

        this->rMaskedMsgs = new AlignedVector<MaskedMsg>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();

}


coproto::task<void> psu::Receiver::setup(Socket& sock, ItemSet& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0),
             iblt_tab_len = size_t(0));

        this->set_items = &set_items;
        PsuDebugLog("receiver", "setup begin");

        if (this->rMaskedMsgs != nullptr) {
            delete this->rMaskedMsgs;
            this->rMaskedMsgs = nullptr;
        }
        if (this->iblt != nullptr) {
            delete this->iblt;
            this->iblt = nullptr;
        }
        this->consumed_send_ots = 0;
        this->consumed_recv_ots = 0;
        this->curr_round = 0;
        this->num_peel_iterations = 0;
        this->round_pld_els.clear();
        this->round_recvr_owned_pld_els.clear();
        this->round_recvr_owned_pld_seeds.clear();
        this->iblt_remove_unique_hash_evals.clear();
        iblt_tab_len = iblt_5h::calc_tab_len(this->recvr_set_size + this->sndr_set_size, this->iblt_mult_fac);
        this->peeled_bm.reset(iblt_tab_len);

        t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver setup started." << std::endl;

        PsuDebugLog("receiver", "setup:eq_seeds start");
        MC_AWAIT(setup_recvr_eq_seeds(sock, *this));
        PsuDebugLog("receiver", "setup:eq_seeds done");

        // std::cout << "Receiver eq seeds setup finished." << std::endl;

        PsuDebugLog("receiver", "setup:ot_corr start");
        MC_AWAIT(setup_receiver_ots_correlations(sock, *this, *(this->iblt), this->sndr_set_size, this->set_items->size(), this->baseRecv, this->baseChoices));
        PsuDebugLog("receiver", "setup:ot_corr done");

        // std::cout << "Receiver OTs setup finished." << std::endl;

        this->rMaskedMsgs = new AlignedVector<MaskedMsg>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        PsuDebugLog("receiver", "setup done, ms=" + std::to_string(duration));

    MC_END();
}

coproto::task<void> psu::Receiver::wan_setup(Socket& sock, ItemSet& set_items) {
    MC_BEGIN(Proto, this, &sock, &set_items,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

        this->set_items = &set_items;

        t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver setup started." << std::endl;

        MC_AWAIT(setup_recvr_eq_seeds(sock, *this));

        // std::cout << "Receiver eq seeds setup finished." << std::endl;

        MC_AWAIT(setup_receiver_ots_correlations(sock, *this, *(this->iblt), this->sndr_set_size, this->set_items->size(), this->baseRecv, this->baseChoices));

        // std::cout << "Receiver OTs setup finished." << std::endl;

        this->rMaskedMsgs = new AlignedVector<MaskedMsg>(psu::max_num_bin_probes_per_round(*(this->iblt)));

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    MC_END();
}

static void comp_u_vector_peel_round(Sender& sender, 
                                     iblt_5h& sender_iblt, 
                                     PRNG& prng,  
                                     span<block>& first_ots_out,
                                     size_t round_num,
                                     const AlignedVector<size_t>& probe_idxs, 
                                     AlignedUnVector<block>& uv) {

    Item* sum = sender_iblt.sum;
    size_t* cnt = sender_iblt.cnt;
    const size_t max_pts = probe_idxs.size();
    sender.uv_slot_scratch.resize(max_pts);
    sender.uv_use_oprf_scratch.resize(max_pts);
    sender.oprf_pts_scratch.resize(max_pts);
    sender.oprf_out_scratch.resize(max_pts);
    block* oprf_pts_arr = sender.oprf_pts_scratch.data();
    block* oprf_out_arr = sender.oprf_out_scratch.data();
    auto& uv_slot = sender.uv_slot_scratch;
    auto& uv_use_oprf = sender.uv_use_oprf_scratch;

    size_t prng_out_len = 0;
    size_t oprf_pts_idx = 0;
    for (size_t i = 0; i < probe_idxs.size(); ++i) {
        size_t idx = probe_idxs[i];
        if (cnt[idx] == 1) {
            uv_use_oprf[i] = 1;
            uv_slot[i] = oprf_pts_idx;
            oprf_pts_arr[oprf_pts_idx++] = sum[idx];
        } else if (first_ots_out[i] != ZeroBlock) {
            uv_use_oprf[i] = 1;
            uv_slot[i] = oprf_pts_idx;
            oprf_pts_arr[oprf_pts_idx++] = first_ots_out[i];
        } else {
            uv_use_oprf[i] = 0;
            uv_slot[i] = prng_out_len++;
        }
    }

    span<block> oprf_pts(oprf_pts_arr, oprf_pts_idx);
    span<block> oprf_out(oprf_out_arr, oprf_pts_idx);

    sender.oprfSender->eval(oprf_pts, oprf_out);

    sender.prng_out_scratch.resize(prng_out_len);
    if (prng_out_len > 0) {
        prng.get<block>(sender.prng_out_scratch.data(), prng_out_len);
    }
    block* prng_out = sender.prng_out_scratch.data();

    FillUvFromEvalOutputs(
        sender,
        round_num,
        probe_idxs.size(),
        [&](size_t pos) { return probe_idxs[pos]; },
        oprf_out_arr,
        prng_out,
        uv);

}

static void comp_u_vector_first_peel_round(Sender& sender, iblt_5h& sender_iblt, PRNG& prng,  span<block>& first_ots_out, AlignedUnVector<block>& uv) {

    Item* sum = sender_iblt.sum;
    size_t* cnt = sender_iblt.cnt;
    size_t tab_len = sender_iblt.tab_len;
    sender.uv_slot_scratch.resize(tab_len);
    sender.uv_use_oprf_scratch.resize(tab_len);
    sender.oprf_pts_scratch.resize(tab_len);
    sender.oprf_out_scratch.resize(tab_len);
    block* oprf_pts_arr = sender.oprf_pts_scratch.data();
    block* oprf_out_arr = sender.oprf_out_scratch.data();
    auto& uv_slot = sender.uv_slot_scratch;
    auto& uv_use_oprf = sender.uv_use_oprf_scratch;

    size_t prng_out_len = 0;
    size_t oprf_pts_idx = 0;
    for (size_t i = 0; i < tab_len; ++i) {
        if (cnt[i] == 1) {
            uv_use_oprf[i] = 1;
            uv_slot[i] = oprf_pts_idx;
            oprf_pts_arr[oprf_pts_idx++] = sum[i];
        } else if (first_ots_out[i] != ZeroBlock) {
            uv_use_oprf[i] = 1;
            uv_slot[i] = oprf_pts_idx;
            oprf_pts_arr[oprf_pts_idx++] = first_ots_out[i];
        } else {
            uv_use_oprf[i] = 0;
            uv_slot[i] = prng_out_len++;
        }
    }

    span<block> oprf_pts(oprf_pts_arr, oprf_pts_idx);
    span<block> oprf_out(oprf_out_arr, oprf_pts_idx);

    auto t0 = std::chrono::high_resolution_clock::now();

    sender.oprfSender->eval(oprf_pts, oprf_out);

    sender.prng_out_scratch.resize(prng_out_len);
    if (prng_out_len > 0) {
        prng.get<block>(sender.prng_out_scratch.data(), prng_out_len);
    }
    block* prng_out = sender.prng_out_scratch.data();

    auto t1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    //std::cout << "Sender first peel round oprf eval time (ms): " << duration << std::endl;

    FillUvFromEvalOutputs(
        sender,
        0,
        tab_len,
        [](size_t pos) { return pos; },
        oprf_out_arr,
        prng_out,
        uv);

    //auto t1 = std::chrono::high_resolution_clock::now();
    //auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    //std::cout << "Sender first peel round u vector computation time (ms): " << duration << std::endl;

}

/*static inline void populate_probe_bitmap(BitVector& probe_bitmap, iblt_5h& iblt, uint64_t elem, uint64_t already_probed_bin) {
    
    size_t tab_idxs[iblt_5h::NUM_HASH_FUNCS];
    iblt.hash_eval(elem, tab_idxs);

    for (size_t i = 0; i < iblt_5h::NUM_HASH_FUNCS; ++i) {
       probe_bitmap[tab_idxs[i]] = already_probed_bin != tab_idxs[i]; 
    }

}*/

static coproto::task<void> sender_first_peel_round(Socket& sock, 
                                    Sender& sender,
                                    iblt_5h& iblt,
                                    ItemSet& pld_els,
                                    ItemVec& round_sender_owned_pld_els,
                                    ItemSet& sender_in_set,
                                    ItemVec& round_pld_els,
                                    BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &sender, &iblt, &pld_els, &round_sender_owned_pld_els, &sender_in_set, &round_pld_els, &peeled_bm,
             cnt = (size_t*) nullptr,
             sum = (Item*) nullptr,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             maskedChoice1 = uint8_t(0),
             randChoices = (BitVector*) nullptr,
             consumed_recv_ots = size_t(0),
             consumed_send_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             sMaskedMsgs = (AlignedUnVector<MaskedMsg>*) nullptr,
             intChoice = uint8_t(0),
             randRecvOtMsgs = (block*) nullptr,
             randSendMsgs = (AlignedVector<std::array<block, 2>>*) nullptr,
             first_ots_out = span<block>(),
             uv = (AlignedUnVector<block>*) nullptr,
             round_pld_els_size = size_t(0),
             round_peeled_bins_size = size_t(0),
             round_peeled_bin_idxs = (std::vector<uint32_t>*) nullptr,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        sMaskedChoices = &sender.sMaskedChoicesScratch;
        sMaskedChoices->resize(iblt.tab_len);
        randChoices = sender.otCorrRecvChoices;

        cnt = sender.iblt->cnt;

        consumed_recv_ots = sender.consumed_recv_ots;

        t0 = std::chrono::high_resolution_clock::now();

        psu::msk_cnt0_choice_bits(iblt.tab_len, cnt, *sMaskedChoices, *randChoices, consumed_recv_ots);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << " (Sender) choice masking time (ms) during round 1: " << duration << std::endl;

        MC_AWAIT(sock.send(*sMaskedChoices));

        rMaskedMsgs = sender.rMaskedMsgs;
        MC_AWAIT(sock.recvResize(*rMaskedMsgs));

        randRecvOtMsgs = sender.otCorrRecvMsgs->data();
        t0 = std::chrono::high_resolution_clock::now();

        #pragma omp parallel for if (iblt.tab_len > 4096)
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            const uint8_t int_choice = (cnt[i] == 0);
            randRecvOtMsgs[i + consumed_recv_ots] ^= (*rMaskedMsgs)[i][int_choice];
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
       // std::cout << "Sender first peel round unmasking time (ms): " << duration << std::endl;

        first_ots_out = sender.otCorrRecvMsgs->subspan(consumed_recv_ots, iblt.tab_len);
        sender.consumed_recv_ots += iblt.tab_len;

        uv = &sender.uv_scratch;
        uv->resize(iblt.tab_len);

        t0 = std::chrono::high_resolution_clock::now();

        comp_u_vector_first_peel_round(sender, iblt, sender.prng, first_ots_out, *uv);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender first peel round u vector computation time (ms): " << duration << std::endl;

        rMaskedChoices = &sender.rMaskedChoicesScratch;
        rMaskedChoices->resize(2 * iblt.tab_len);
        MC_AWAIT(sock.recv(*rMaskedChoices));
        
        consumed_send_ots = sender.consumed_send_ots;
        sum = sender.iblt->sum;
        randSendMsgs = sender.otCorrSendMsgs;
        sMaskedMsgs = &sender.sMaskedMsgsScratch;
        sMaskedMsgs->resize(iblt.tab_len);
        #pragma omp parallel for if (iblt.tab_len > 4096)
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            const uint8_t masked_choice = (uint8_t) (*rMaskedChoices)[2*i];
            const uint8_t masked_choice1 = (uint8_t) (*rMaskedChoices)[2*i + 1];
            const block cond_probed_sum = (cnt[i] == 1) ? sum[i] : ZeroBlock;

            (*sMaskedMsgs)[i][0] = cond_probed_sum ^ (*randSendMsgs)[2*i + consumed_send_ots][masked_choice] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][masked_choice1];
            (*sMaskedMsgs)[i][1] = (*uv)[i] ^ (*randSendMsgs)[2*i + consumed_send_ots][1^masked_choice] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][masked_choice1];

        }

        MC_AWAIT(sock.send(*sMaskedMsgs));
        
        sender.consumed_send_ots += 2*iblt.tab_len;
        
        MC_AWAIT(sock.recv(round_pld_els_size));
        MC_AWAIT(sock.recv(round_peeled_bins_size));

        round_peeled_bin_idxs = &sender.round_peeled_bin_idxs;
        round_peeled_bin_idxs->resize(round_peeled_bins_size);
        round_pld_els.resize(round_pld_els_size);

        if (round_peeled_bins_size > 0) {
            MC_AWAIT(sock.recv(*round_peeled_bin_idxs));
            for (uint32_t idx : *round_peeled_bin_idxs) {
                peeled_bm[idx] = 1;
            }
        }

        if (round_pld_els_size > 0) {
            MC_AWAIT(sock.recv(round_pld_els));
        }

        for (size_t i = 0; i < round_pld_els.size(); ++i) {
            pld_els.insert(round_pld_els[i]);
           if (sender_in_set.contains(round_pld_els[i])) {
                round_sender_owned_pld_els.push_back(round_pld_els[i]);
            }
        }

    MC_END();
}

static coproto::task<void> receiver_first_peel_round(Socket& sock, 
                                       Receiver& receiver,
                                       iblt_5h& iblt,
                                       ItemSet& pld_els,
                                       ItemVec& round_recvr_owned_pld_els,
                                       vector<block>& round_recvr_owned_pld_seeds,
                                       ItemVec& round_pld_els,
                                       BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &receiver, &iblt, &pld_els, &round_recvr_owned_pld_els, &round_recvr_owned_pld_seeds, &round_pld_els, &peeled_bm,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices =  (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             cnt = (size_t*) nullptr,
             sum = (Item*) nullptr,
             seed_sum = (block*) nullptr,
             consumed_send_ots = size_t(0),
             consumed_recv_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             sMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             //randSendMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (uint64_t*) nullptr,
             randChoices = (BitVector*) nullptr,
             round_peeled_bin_idxs = (std::vector<uint32_t>*) nullptr,
             intChoice = uint8_t(0),
             ot_out = block(0,0),
             randRecvOtMsgs = (block*) nullptr,
             b = block(0, 0),
             aes = AES(),
            t0 = std::chrono::high_resolution_clock::time_point{},
            t1 = std::chrono::high_resolution_clock::time_point{},
            duration = int64_t(0));

        sMaskedChoices = &receiver.sMaskedChoicesScratch;
        sMaskedChoices->resize(iblt.tab_len);
        rMaskedChoices = &receiver.rMaskedChoicesScratch;
        rMaskedChoices->resize(2 * iblt.tab_len);
        round_peeled_bin_idxs = &receiver.round_peeled_bin_idxs;
        round_peeled_bin_idxs->clear();
        rMaskedMsgs = receiver.rMaskedMsgs;

        MC_AWAIT(sock.recv(*sMaskedChoices));

        cnt = receiver.iblt->cnt;
        sum = receiver.iblt->sum;
        seed_sum = receiver.iblt->seedsum;
        //randSendMsgs = receiver.otCorrSendMsgs;
        //randSendMsgs = reinterpret_cast<uint64_t*>(receiver.otCorrSendMsgs->data());

        t0 = std::chrono::high_resolution_clock::now();

        consumed_send_ots = receiver.consumed_send_ots;
        #pragma omp parallel for if (iblt.tab_len > 4096)
        for (size_t i = 0; i < iblt.tab_len; ++i) {
           const uint8_t masked_choice = (uint8_t) (*sMaskedChoices)[i];
           
           (*rMaskedMsgs)[i][0] = (*receiver.otCorrSendMsgs)[i + consumed_send_ots][masked_choice];
           (*rMaskedMsgs)[i][1] = (((*receiver.iblt->cnt_vec)[i] == 1) ? (*receiver.iblt->sum_vec)[i] : ZeroBlock) ^ (*receiver.otCorrSendMsgs)[i + consumed_send_ots][1 ^ masked_choice];

        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver first peel round unmasking time (ms): " << duration << std::endl;

        receiver.consumed_send_ots += iblt.tab_len;

        MC_AWAIT(sock.send(*rMaskedMsgs));

        randChoices = receiver.otCorrRecvChoices;
        consumed_recv_ots = receiver.consumed_recv_ots;
        #pragma omp simd
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            (*rMaskedChoices)[2*i] = (cnt[i] == 1) ^ (*randChoices)[2*i + consumed_recv_ots];
            (*rMaskedChoices)[2*i + 1] = (cnt[i] > 1) ^ (*randChoices)[2*i + 1 + consumed_recv_ots];
        }

        MC_AWAIT(sock.send(*rMaskedChoices));

        sMaskedMsgs = &receiver.sMaskedMsgsScratch;
        sMaskedMsgs->resize(iblt.tab_len);
        MC_AWAIT(sock.recv(*sMaskedMsgs));
        randRecvOtMsgs = receiver.otCorrRecvMsgs->data();
        for (size_t i = 0; i < iblt.tab_len; ++i) {
            if(cnt[i] > 1) continue;
            intChoice = (uint8_t) cnt[i];

            ot_out = (*sMaskedMsgs)[i][intChoice] ^ randRecvOtMsgs[2*i + consumed_recv_ots]
                     ^ randRecvOtMsgs[2*i + 1 + consumed_recv_ots];

            if (cnt[i] == 0 && ot_out != ZeroBlock) {

                if (!static_cast<bool>(peeled_bm[i])) {
                    peeled_bm[i] = 1;
                    round_peeled_bin_idxs->push_back(static_cast<uint32_t>(i));
                }
                if(pld_els.insert(ot_out).second) {
                    round_pld_els.push_back(ot_out);                    

                    //if (recvr_in_set.find(ot_out) != recvr_in_set.end()) { This is probably not needed
                    //    round_recvr_owned_pld_els.push_back(ot_out);
                    //}
                }

            } else if (cnt[i] == 1) {
                b = block(0, i);

                aes.setKey(seed_sum[i]);

                if (ot_out == aes.ecbEncBlock(b)) {

                    if (!static_cast<bool>(peeled_bm[i])) {
                        peeled_bm[i] = 1;
                        round_peeled_bin_idxs->push_back(static_cast<uint32_t>(i));
                    }

                    if (pld_els.insert(sum[i]).second) {
                        round_pld_els.push_back(sum[i]);
                        round_recvr_owned_pld_els.push_back(sum[i]);
                        round_recvr_owned_pld_seeds.push_back(seed_sum[i]);

                        //if (recvr_in_set.find(sum[i]) != recvr_in_set.end()) { // This is probably not needed
                        //    round_recvr_owned_pld_els.push_back(sum[i]);
                        //}
                    }
                }
            }
        }

        receiver.consumed_recv_ots += 2*iblt.tab_len;

        MC_AWAIT(sock.send(round_pld_els.size()));
        MC_AWAIT(sock.send(round_peeled_bin_idxs->size()));

        if(round_peeled_bin_idxs->size() > 0) {
            MC_AWAIT(sock.send(*round_peeled_bin_idxs));
        }

        if(round_pld_els.size() > 0) {
            MC_AWAIT(sock.send(round_pld_els));
        }

    MC_END();
}

static coproto::task<void> sender_peel_round(Socket& sock, 
                                             Sender& sender,
                                             iblt_5h& iblt,
                                             size_t round_num,
                                             AlignedVector<size_t>& probe_idxs,
                                             ItemSet& pld_els,
                                             ItemVec& round_sender_owned_pld_els,
                                             ItemSet& sender_in_set,
                                             ItemVec& round_pld_els,
                                             BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &sender, &iblt, round_num, &probe_idxs, &pld_els, &round_sender_owned_pld_els, &sender_in_set, &round_pld_els, &peeled_bm,
             cnt = (size_t*) nullptr,
             sum = (Item*) nullptr,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             maskedChoice1 = uint8_t(0),
             randChoices = (BitVector*) nullptr,
             consumed_recv_ots = size_t(0),
             consumed_send_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             sMaskedMsgs = (AlignedUnVector<MaskedMsg>*) nullptr,
             intChoice = uint8_t(0),
             randRecvOtMsgs = (block*) nullptr,
             randSendMsgs = (AlignedVector<std::array<block, 2>>*) nullptr,
             first_ots_out = span<block>(),
             uv = (AlignedUnVector<block>*) nullptr,
             probe_idx = size_t(0),
             round_pld_els_size = size_t(0),
             round_peeled_bins_size = size_t(0),
             round_peeled_bin_idxs = (std::vector<uint32_t>*) nullptr,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));

        sMaskedChoices = &sender.sMaskedChoicesScratch;
        sMaskedChoices->resize(probe_idxs.size());
        randChoices = sender.otCorrRecvChoices;

        cnt = sender.iblt->cnt;
        consumed_recv_ots = sender.consumed_recv_ots;

        t0 = std::chrono::high_resolution_clock::now();

        psu::msk_cnt0_choice_bits(probe_idxs, cnt, *sMaskedChoices, *randChoices, consumed_recv_ots);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << " (Sender) choice masking time (ms) during round " << round_num << ": " << duration << std::endl;

        MC_AWAIT(sock.send(*sMaskedChoices));

        rMaskedMsgs = sender.rMaskedMsgs;

        MC_AWAIT(sock.recvResize(*rMaskedMsgs));

        t0 = std::chrono::high_resolution_clock::now();
        randRecvOtMsgs = sender.otCorrRecvMsgs->data();
        #pragma omp parallel for if (probe_idxs.size() > 4096)
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            const size_t local_probe_idx = probe_idxs[i];
            const uint8_t int_choice = (cnt[local_probe_idx] == 0);
            randRecvOtMsgs[i + consumed_recv_ots] ^= (*rMaskedMsgs)[i][int_choice];
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender peel round " << round_num << " unmasking time (ms): " << duration << std::endl;

        first_ots_out = sender.otCorrRecvMsgs->subspan(consumed_recv_ots, probe_idxs.size());
        sender.consumed_recv_ots += probe_idxs.size();
        
        uv = &sender.uv_scratch;
        uv->resize(probe_idxs.size());

        t0 = std::chrono::high_resolution_clock::now();

        comp_u_vector_peel_round(sender, iblt, sender.prng, first_ots_out, round_num, probe_idxs, *uv);

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Sender peel round " << round_num << " u vector computation time (ms): " << duration << std::endl;

        rMaskedChoices = &sender.rMaskedChoicesScratch;
        rMaskedChoices->resize(2 * probe_idxs.size());
        MC_AWAIT(sock.recv(*rMaskedChoices));

        consumed_send_ots = sender.consumed_send_ots;
        sum = sender.iblt->sum;
        randSendMsgs = sender.otCorrSendMsgs;
        
        sMaskedMsgs = &sender.sMaskedMsgsScratch;
        sMaskedMsgs->resize(probe_idxs.size());
        
        #pragma omp parallel for if (probe_idxs.size() > 4096)
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            const size_t local_probe_idx = probe_idxs[i];
            const uint8_t masked_choice = (uint8_t) (*rMaskedChoices)[2*i];
            const uint8_t masked_choice1 = (uint8_t) (*rMaskedChoices)[2*i + 1];

            const block cond_probed_sum =
                (cnt[local_probe_idx] == 1) ? sum[local_probe_idx] : ZeroBlock;

            (*sMaskedMsgs)[i][0] = cond_probed_sum ^ (*randSendMsgs)[2*i + consumed_send_ots][masked_choice] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][masked_choice1];
            (*sMaskedMsgs)[i][1] = (*uv)[i] ^ (*randSendMsgs)[2*i + consumed_send_ots][1^masked_choice] ^ (*randSendMsgs)[2*i + 1 + consumed_send_ots][masked_choice1];
        }

        MC_AWAIT(sock.send(*sMaskedMsgs));

        sender.consumed_send_ots += 2*probe_idxs.size();

        MC_AWAIT(sock.recv(round_pld_els_size));
        MC_AWAIT(sock.recv(round_peeled_bins_size));

        round_peeled_bin_idxs = &sender.round_peeled_bin_idxs;
        round_peeled_bin_idxs->resize(round_peeled_bins_size);
        round_pld_els.resize(round_pld_els_size);
        
        if(round_peeled_bins_size > 0) {
            MC_AWAIT(sock.recv(*round_peeled_bin_idxs));
            for (uint32_t idx : *round_peeled_bin_idxs) {
                peeled_bm[idx] = 1;
            }
        }

        if(round_pld_els_size > 0) {
            MC_AWAIT(sock.recv(round_pld_els));
        }

        for (size_t i = 0; i < round_pld_els.size(); ++i) {
            pld_els.insert(round_pld_els[i]);
            if (sender_in_set.contains(round_pld_els[i])) {
                round_sender_owned_pld_els.push_back(round_pld_els[i]);
            }
        }


    MC_END();

}


static coproto::task<void> receiver_peel_round(Socket& sock, 
                                               Receiver& receiver,
                                               iblt_5h& iblt,
                                               size_t round_num,
                                               AlignedVector<size_t>& probe_idxs,
                                               ItemSet& pld_els,
                                               ItemVec& round_recvr_owned_pld_els,
                                               vector<block>& round_recvr_owned_pld_seeds,
                                               ItemVec& round_pld_els,
                                               BitVector& peeled_bm) {
    MC_BEGIN(Proto, &sock, &receiver, &iblt, &pld_els, &probe_idxs, round_num, &round_recvr_owned_pld_els, &round_recvr_owned_pld_seeds, &round_pld_els, &peeled_bm,
             sMaskedChoices = (BitVector*) nullptr,
             rMaskedChoices = (BitVector*) nullptr,
             maskedChoice = uint8_t(0),
             cnt = (size_t*) nullptr,
             sum = (Item*) nullptr,
             seed_sum = (block*) nullptr,
             consumed_send_ots = size_t(0),
             consumed_recv_ots = size_t(0),
             rMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             sMaskedMsgs = (AlignedVector<MaskedMsg>*) nullptr,
             //randSendMsgs = (AlignedVector<array<uint64_t, 2>>*) nullptr,
             //randSendMsgs = (uint64_t*) nullptr,
             rMaskedMsgsSpan = span<MaskedMsg>(),
             randChoices = (BitVector*) nullptr,
             intChoice = uint8_t(0),
             ot_out = block(0,0),
             randRecvOtMsgs = (block*) nullptr,
             probe_idx = size_t(0),
             round_peeled_bin_idxs = (std::vector<uint32_t>*) nullptr,
             b = block(0, 0),
             aes = AES(),
             //peeled_bin_bm = (BitVector*) nullptr,
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        round_pld_els.reserve(probe_idxs.size());

        sMaskedChoices = &receiver.sMaskedChoicesScratch;
        sMaskedChoices->resize(probe_idxs.size());
        rMaskedMsgs = receiver.rMaskedMsgs;
        round_peeled_bin_idxs = &receiver.round_peeled_bin_idxs;
        round_peeled_bin_idxs->clear();

        // std::cout << "Receiving sMaskedChoices: " << probe_idxs.size() << std::endl;

        //std::cout << " (Receiver) Before MC_AWAIT(sock.recv(*sMaskedChoices));" << std::endl;

        MC_AWAIT(sock.recv(*sMaskedChoices));

        //std::cout << " (After) Before MC_AWAIT(sock.recv(*sMaskedChoices));" << std::endl;

        //t0 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t0 - t1).count();
        //std::cout << "t0 in milliseconds since epoch: " << duration << std::endl;

        // std::cout << "Received sMaskedChoices." << std::endl;

        cnt = receiver.iblt->cnt;
        sum = receiver.iblt->sum;
        seed_sum = receiver.iblt->seedsum;
        //randSendMsgs = receiver.otCorrSendMsgs;
        //randSendMsgs = reinterpret_cast<uint64_t*>(receiver.otCorrSendMsgs->data());

        consumed_send_ots = receiver.consumed_send_ots;

        t0 = std::chrono::high_resolution_clock::now();

        #pragma omp parallel for if (probe_idxs.size() > 4096)
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            const size_t local_probe_idx = probe_idxs[i];
            const uint8_t masked_choice = (uint8_t) (*sMaskedChoices)[i];

            (*rMaskedMsgs)[i][0] = (*receiver.otCorrSendMsgs)[i + consumed_send_ots][masked_choice];
            (*rMaskedMsgs)[i][1] = ((cnt[local_probe_idx] == 1) ? sum[local_probe_idx] : ZeroBlock) ^ (*receiver.otCorrSendMsgs)[i + consumed_send_ots][1 ^ masked_choice];
        }

        t1 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver peel round " << round_num << " unmasking time (ms): " << duration << std::endl;

        receiver.consumed_send_ots += probe_idxs.size();
        
        rMaskedMsgsSpan = rMaskedMsgs->subspan(0, probe_idxs.size());

        // std::cout << "Sending rMaskedMsgs." << std::endl;

        //t0 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t0 - t1).count();
        //std::cout << "rMaskedMsgs send time is " << duration << " ms during round " << round_num << std::endl;
        //std::cout << "rMaskedMsgs size: " << (rMaskedMsgsSpan.size() * sizeof(MaskedMsg) * 8 / 1000000.0) << " megabits" << std::endl;

        MC_AWAIT(sock.send(std::move(rMaskedMsgsSpan)));

        // std::cout << "Sent rMaskedMsgs." << std::endl;

        randChoices = receiver.otCorrRecvChoices;
        consumed_recv_ots = receiver.consumed_recv_ots;
        rMaskedChoices = &receiver.rMaskedChoicesScratch;
        rMaskedChoices->resize(2 * probe_idxs.size());
        #pragma omp simd
        for (size_t i = 0; i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            (*rMaskedChoices)[2*i] =  (cnt[probe_idx] == 1) ^ (*randChoices)[2*i + consumed_recv_ots];
            (*rMaskedChoices)[2*i + 1] = (cnt[probe_idx] > 1) ^ (*randChoices)[2*i + 1 + consumed_recv_ots];
        }

        MC_AWAIT(sock.send(*rMaskedChoices));

        sMaskedMsgs = &receiver.sMaskedMsgsScratch;
        sMaskedMsgs->resize(probe_idxs.size());
        MC_AWAIT(sock.recv(*sMaskedMsgs));

        //t0 = std::chrono::high_resolution_clock::now();
        //randRecvOtMsgs = receiver.otCorrRecvMsgs->data();
        //peeled_bin_bm = new BitVector(iblt.tab_len);
        randRecvOtMsgs = receiver.otCorrRecvMsgs->data();
        for (size_t i=0;i < probe_idxs.size(); ++i) {
            probe_idx = probe_idxs[i];
            if(cnt[probe_idx] > 1) continue;
            intChoice = (uint8_t) cnt[probe_idx];

            ot_out = (*sMaskedMsgs)[i][intChoice] ^ randRecvOtMsgs[2*i + consumed_recv_ots]
                     ^ randRecvOtMsgs[2*i + 1 + consumed_recv_ots];

            if (cnt[probe_idx] == 0 && ot_out != ZeroBlock) {
                
                if (!static_cast<bool>(peeled_bm[probe_idx])) {
                    peeled_bm[probe_idx] = 1;
                    round_peeled_bin_idxs->push_back(static_cast<uint32_t>(probe_idx));
                }
                if(pld_els.insert(ot_out).second) {
                    //populate_probe_bitmap(*peeled_bin_bm, iblt, ot_out, probe_idx);

                    round_pld_els.push_back(ot_out);

                    //if (recvr_in_set.find(ot_out) != recvr_in_set.end()) { // This is probably not needed
                    //    round_recvr_owned_pld_els.push_back(ot_out);
                    //}
                }
            } else if (cnt[probe_idx] == 1) {
                b = block(round_num, probe_idx);

                aes.setKey(seed_sum[probe_idx]);

              
                if (ot_out == aes.ecbEncBlock(b)) {
                    
                    if (!static_cast<bool>(peeled_bm[probe_idx])) {
                        peeled_bm[probe_idx] = 1;
                        round_peeled_bin_idxs->push_back(static_cast<uint32_t>(probe_idx));
                    }
                    
                    if (pld_els.insert(sum[probe_idx]).second) {
                        //populate_probe_bitmap(*peeled_bin_bm, iblt, sum[probe_idx], probe_idx);

                        round_pld_els.push_back(sum[probe_idx]);
                        round_recvr_owned_pld_els.push_back(sum[probe_idx]);
                        round_recvr_owned_pld_seeds.push_back(seed_sum[probe_idx]);

                        //if (recvr_in_set.find(sum[probe_idx]) != recvr_in_set.end()) {
                        //    round_recvr_owned_pld_els.push_back(sum[probe_idx]);
                        //}
                    }
                }
            }

        }

        //t1 = std::chrono::high_resolution_clock::now();
        //duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        //std::cout << "Receiver peel round " << round_num << " finished in " << duration << " ms." << std::endl;

        receiver.consumed_recv_ots += 2*probe_idxs.size();

        MC_AWAIT(sock.send(round_pld_els.size()));
        MC_AWAIT(sock.send(round_peeled_bin_idxs->size()));

        if(round_peeled_bin_idxs->size() > 0) {
            MC_AWAIT(sock.send(*round_peeled_bin_idxs));
        }

        if(round_pld_els.size() > 0) {
            MC_AWAIT(sock.send(round_pld_els));
            //MC_AWAIT(sock.send(std::move(*peeled_bin_bm)));
        }

        //delete peeled_bin_bm;

    MC_END();

}


coproto::task<void> psu::Sender::send(Socket& sock, ItemSet& pld_els) {
    MC_BEGIN(Proto, this, &sock, &pld_els,
             round_num = size_t(0),
             round_pld_els = ItemVec());
        PsuDebugLog("sender", "send begin");
        pld_els.reserve(recvr_set_size + set_items->size());

         //std::cout << "Sender first peel round started." << std::endl;

        MC_AWAIT(sender_first_peel_round(sock, *this, *(this->iblt), pld_els, round_sender_owned_pld_els, *(this->set_items), round_pld_els, this->peeled_bm));        

        // std::cout << "Sender first peel round finished." << std::endl;

        this->iblt->removeKeys(round_sender_owned_pld_els);
        this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);

        round_num = 1;
        PsuDebugLog("sender", "send round=0 done, peeled=" + std::to_string(round_pld_els.size()) +
                               ", next_probe=" + std::to_string(iblt_remove_unique_hash_evals.size()));

        while (iblt_remove_unique_hash_evals.size() > 0) {
            round_sender_owned_pld_els.clear();
            round_pld_els.clear();
            
             //std::cout << "Sender peel round " << round_num << " started, with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

             //std::cout << "Sender processing round " << round_num << " with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

            MC_AWAIT(sender_peel_round(sock, *this, *(this->iblt), round_num, iblt_remove_unique_hash_evals, pld_els, round_sender_owned_pld_els, *(this->set_items), round_pld_els, this->peeled_bm));

            //std::cout << "Sender peel round " << round_num << " finished, with " << round_pld_els.size() << " peeled elements." << std::endl;

            iblt_remove_unique_hash_evals.clear();

            this->iblt->removeKeys(round_sender_owned_pld_els); 
            this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm); 
            PsuDebugLog("sender", "send round=" + std::to_string(round_num) +
                                   " done, peeled=" + std::to_string(round_pld_els.size()) +
                                   ", next_probe=" + std::to_string(iblt_remove_unique_hash_evals.size()));

            round_num++;
        }

       // std::cout << "Sender finished peeling." << std::endl;

        this->num_peel_iterations = round_num;
        PsuDebugLog("sender", "send done, peel_iters=" + std::to_string(this->num_peel_iterations));

        // std::cout << "Sender finished peeling." << std::endl;

    MC_END();
}

coproto::task<void> psu::Receiver::recv(Socket& sock, ItemSet& pld_els) {
    MC_BEGIN(Proto, this, &sock, &pld_els,
             round_num = size_t(0),
             t0 = std::chrono::high_resolution_clock::time_point{},
             t1 = std::chrono::high_resolution_clock::time_point{},
             duration = int64_t(0));
        pld_els.reserve(sndr_set_size + set_items->size());
        PsuDebugLog("receiver", "recv begin");

        //t0 = std::chrono::high_resolution_clock::now();

        // std::cout << "Receiver first peel round started." << std::endl;


        MC_AWAIT(receiver_first_peel_round(sock, *this, *(this->iblt), pld_els, round_recvr_owned_pld_els, round_recvr_owned_pld_seeds, round_pld_els, this->peeled_bm));


        // std::cout << "Receiver first peel round finished." << std::endl;

        this->iblt->remove(round_recvr_owned_pld_els, round_recvr_owned_pld_seeds);
        this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);
        PsuDebugLog("receiver", "recv round=0 done, peeled=" + std::to_string(round_pld_els.size()) +
                                 ", next_probe=" + std::to_string(iblt_remove_unique_hash_evals.size()));

       // t1 = std::chrono::high_resolution_clock::now();
       // duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
      //  std::cout << "Receiver first peel round finished in " << duration << " ms" << std::endl;
      //  std::cout << "Parties peeled " << round_pld_els.size() << " elements during first peel round." << std::endl;

        round_num = 1;

       // std::cout << "Round 1 Done" << std::endl; 

        while (iblt_remove_unique_hash_evals.size() > 0) {
          //  t0 = std::chrono::high_resolution_clock::now();

            round_recvr_owned_pld_els.clear();
            round_recvr_owned_pld_seeds.clear();
            round_pld_els.clear();

            //std::cout << "Receiver processing round " << round_num << " with " << iblt_remove_unique_hash_evals.size() << " unique hash evaluations." << std::endl;

            //std::cout << "Receiver peel round " << round_num << " started." << std::endl;

            MC_AWAIT(receiver_peel_round(sock, *this, *(this->iblt), round_num, iblt_remove_unique_hash_evals, pld_els, round_recvr_owned_pld_els, round_recvr_owned_pld_seeds, round_pld_els, this->peeled_bm));

            //std::cout << "Round " << round_num + 1 << " Done" << std::endl;

            // std::cout << "Receiver peel round " << round_num << " finished." << std::endl;

            iblt_remove_unique_hash_evals.clear();

            this->iblt->remove(round_recvr_owned_pld_els, round_recvr_owned_pld_seeds); 
            this->iblt->unique_hash_evals(round_pld_els, iblt_remove_unique_hash_evals, this->peeled_bm);
            PsuDebugLog("receiver", "recv round=" + std::to_string(round_num) +
                                     " done, peeled=" + std::to_string(round_pld_els.size()) +
                                     ", next_probe=" + std::to_string(iblt_remove_unique_hash_evals.size()));

          //  t1 = std::chrono::high_resolution_clock::now();
         //   duration = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
         //   std::cout << "Receiver peel round " << round_num << " finished in " << duration << " ms" << std::endl;

            //std::cout << "Parties peeled " << round_pld_els.size() << " elements during round " << round_num << "." << std::endl;
            //std::cout << "Amount of bins to probe in next round: " << iblt_remove_unique_hash_evals.size() << std::endl;

            round_num++;
        }

       // std::cout << "Receiver finished peeling." << std::endl;

        this->num_peel_iterations = round_num;
        PsuDebugLog("receiver", "recv done, peel_iters=" + std::to_string(this->num_peel_iterations));

    MC_END();
}

void psu::msk_cnt0_choice_bits(size_t iblt_tab_len, size_t* cnt, osuCrypto::BitVector& maskedChoices, osuCrypto::BitVector& randChoices, size_t randChoicesOffset) {
    // #pragma omp simd aligned(cnt:32)
    for (size_t i = 0; i < iblt_tab_len; ++i) {
        maskedChoices[i] = (cnt[i] == 0) ^ randChoices[i + randChoicesOffset];
    }
}

void psu::msk_cnt0_choice_bits(AlignedVector<size_t>& probe_idxs, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset) {
    

    for (size_t i = 0; i < probe_idxs.size(); ++i) {
        size_t probe_idx = probe_idxs[i];
        maskedChoices[i] = (cnt[probe_idx] == 0) ^ randChoices[i + randChoicesOffset];
    }

}
