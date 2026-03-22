#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "examples/upsi/psu/iblt_based_psu/iblt_h5.hpp"
#include "examples/upsi/psu/iblt_based_psu/unordered_dense_compat.h"

#include "examples/upsi/psu/iblt_based_psu/volePSI/RsOprf.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/MultiKeyAES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Socket/Socket.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"

namespace psu {
    using Item = iblt_5h::Item;
    using ItemSet = ankerl::unordered_dense::set<Item>;
    using ItemVec = std::vector<Item>;
    using MaskedMsg = std::array<osuCrypto::block, 2>;

    inline size_t max_num_bin_probes(size_t iblt_tab_len, size_t num_iblt_hash_funcs, size_t sender_set_size, size_t recvr_set_size) {
        size_t max_union_set_size = sender_set_size + recvr_set_size;

        // Strict Fig.5-style probing budget:
        // round-0 probes full table, and each newly peeled item can enqueue all k hashes.
        return iblt_tab_len + max_union_set_size * num_iblt_hash_funcs;
    }

    inline size_t max_num_bin_probes_per_round(iblt_5h& iblt) {
        // In one peel round, up to tab_len items may be peeled, each contributing k probes.
        return iblt.tab_len * iblt_5h::NUM_HASH_FUNCS;
    }

    struct Sender {
        ItemSet* set_items;
        size_t recvr_set_size;
        size_t sndr_set_size;
        iblt_5h* iblt = nullptr;
        osuCrypto::block iblt_seed;
        double iblt_mult_fac = 3.5;
        size_t softspoken_ot_field_size = 2;
        bool oprf_reduced_rounds = false;
        size_t num_peel_iterations = 0;

        osuCrypto::block seed;
        osuCrypto::PRNG prng;

        volePSI::RsOprfSender* oprfSender = nullptr;
        
        osuCrypto::BitVector* otCorrRecvChoices = nullptr;
        osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs = nullptr;
        osuCrypto::AlignedVector<std::array<osuCrypto::block,2>>* otCorrSendMsgs = nullptr;

        osuCrypto::BitVector peeled_bm;
        osuCrypto::AlignedVector<MaskedMsg>* rMaskedMsgs = nullptr;
        ItemVec round_sender_owned_pld_els;
        osuCrypto::AlignedVector<size_t> iblt_remove_unique_hash_evals;
        osuCrypto::BitVector sMaskedChoicesScratch;
        osuCrypto::BitVector rMaskedChoicesScratch;
        osuCrypto::AlignedUnVector<osuCrypto::block> uv_scratch;
        osuCrypto::AlignedUnVector<MaskedMsg> sMaskedMsgsScratch;
        std::vector<uint32_t> round_peeled_bin_idxs;
        osuCrypto::AlignedVector<osuCrypto::block> oprf_pts_scratch;
        osuCrypto::AlignedVector<osuCrypto::block> oprf_out_scratch;
        osuCrypto::AlignedVector<osuCrypto::block> prng_out_scratch;
        std::vector<size_t> uv_slot_scratch;
        std::vector<uint8_t> uv_use_oprf_scratch;
        std::vector<size_t> uv_oprf_pos_scratch;
        //osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs128 = nullptr;
        //osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>* otCorrSendMsgs128 = nullptr;

        osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>> baseSend;
        
        size_t consumed_recv_ots = 0;
        size_t consumed_send_ots = 0;
        uint64_t curr_round = 0;

        Sender(const osuCrypto::block seed, 
               const size_t sndr_set_size, 
               const size_t recvr_set_size, 
               const osuCrypto::block iblt_seed,
               const double iblt_mult_fac,
               const size_t softspoken_ot_field_size,
               const bool oprf_reduced_rounds) : recvr_set_size(recvr_set_size), sndr_set_size(sndr_set_size), iblt_seed(iblt_seed), iblt_mult_fac(iblt_mult_fac), softspoken_ot_field_size(softspoken_ot_field_size), oprf_reduced_rounds(oprf_reduced_rounds), seed(seed) {
            prng.SetSeed(seed);

            auto otRecvr = new osuCrypto::SoftSpokenShOtReceiver<>();
            otRecvr->init(softspoken_ot_field_size, true);

            size_t iblt_tab_len = iblt_5h::calc_tab_len(recvr_set_size + sndr_set_size, iblt_mult_fac);
            size_t max_n_bin_probes = max_num_bin_probes(iblt_tab_len, iblt_5h::NUM_HASH_FUNCS, sndr_set_size, recvr_set_size);
            
            this->otCorrRecvChoices = new osuCrypto::BitVector(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrRecvMsgs = new osuCrypto::AlignedVector<osuCrypto::block>(max_n_bin_probes + otRecvr->baseOtCount());
            //this->otCorrRecvMsgs128 = new osuCrypto::AlignedVector<osuCrypto::block>(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrSendMsgs = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(2*max_n_bin_probes);
            //this->otCorrSendMsgs128 = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(2*max_n_bin_probes);

            round_sender_owned_pld_els.reserve(sndr_set_size + recvr_set_size);
            iblt_remove_unique_hash_evals.reserve(iblt_tab_len);
            peeled_bm.resize(iblt_tab_len);
            sMaskedChoicesScratch.reserve(iblt_tab_len);
            rMaskedChoicesScratch.reserve(2 * iblt_tab_len);
            uv_scratch.reserve(iblt_tab_len);
            sMaskedMsgsScratch.reserve(iblt_tab_len);
            round_peeled_bin_idxs.reserve(iblt_tab_len);
            uv_slot_scratch.reserve(iblt_tab_len);
            uv_use_oprf_scratch.reserve(iblt_tab_len);
            uv_oprf_pos_scratch.reserve(iblt_tab_len);
            //sender_in_set.reserve(sndr_set_size);

            delete otRecvr;
        }

        ~Sender() {
            if (otCorrSendMsgs != nullptr) delete otCorrSendMsgs;
            if (otCorrRecvChoices != nullptr) delete otCorrRecvChoices;
            if (otCorrRecvMsgs != nullptr) delete otCorrRecvMsgs;
            if (oprfSender != nullptr) delete oprfSender;
            if (rMaskedMsgs != nullptr) delete rMaskedMsgs;
            if (iblt != nullptr) delete iblt;
            //if (otCorrRecvMsgs128 != nullptr) delete otCorrRecvMsgs128;
            //if (otCorrSendMsgs128 != nullptr) delete otCorrSendMsgs128;
        }

        coproto::task<void> setup(coproto::Socket& sock, ItemSet& set_items);
        coproto::task<void> wan_setup(coproto::Socket& sock, ItemSet& set_items);

        coproto::task<void> send(coproto::Socket& sock, ItemSet& pld_els);    
    
    };

    struct Receiver {
        ItemSet* set_items;
        size_t sndr_set_size;
        size_t recvr_set_size;
        iblt_5h* iblt = nullptr;
        osuCrypto::block iblt_seed;
        double iblt_mult_fac = 3.5;
        size_t softspoken_ot_field_size = 2;
        bool oprf_reduced_rounds = false;
        size_t num_peel_iterations = 0;
        
        osuCrypto::block seed;
        osuCrypto::PRNG prng;

        osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>* otCorrSendMsgs = nullptr;
        osuCrypto::BitVector* otCorrRecvChoices = nullptr;
        osuCrypto::AlignedVector<osuCrypto::block>* otCorrRecvMsgs = nullptr;

        // The following datastructures are allocated as part of of the sender to avoid unnecessary memory allocations during the protocol.
        osuCrypto::AlignedVector<MaskedMsg>* rMaskedMsgs = nullptr;
        ItemVec round_pld_els;
        ItemVec round_recvr_owned_pld_els;
        osuCrypto::AlignedVector<size_t> iblt_remove_unique_hash_evals;
        std::vector<osuCrypto::block> round_recvr_owned_pld_seeds;     
        osuCrypto::BitVector peeled_bm;   
        osuCrypto::BitVector sMaskedChoicesScratch;
        osuCrypto::BitVector rMaskedChoicesScratch;
        osuCrypto::AlignedVector<MaskedMsg> sMaskedMsgsScratch;
        std::vector<uint32_t> round_peeled_bin_idxs;

        osuCrypto::BitVector baseChoices;
        osuCrypto::AlignedVector<osuCrypto::block> baseRecv;

        size_t consumed_send_ots = 0;
        size_t consumed_recv_ots = 0;
        uint64_t curr_round = 0;

        Receiver(const osuCrypto::block seed, 
                 const size_t recvr_set_size, 
                 const size_t sndr_set_size, 
                 const osuCrypto::block iblt_seed,
                 const double iblt_mult_fac,
                 const size_t softspoken_ot_field_size,
                 const bool oprf_reduced_rounds) : sndr_set_size(sndr_set_size), recvr_set_size(recvr_set_size), iblt_seed(iblt_seed), iblt_mult_fac(iblt_mult_fac), softspoken_ot_field_size(softspoken_ot_field_size), oprf_reduced_rounds(oprf_reduced_rounds), seed(seed) {
            prng.SetSeed(seed);

            auto otRecvr = new osuCrypto::SoftSpokenShOtReceiver<>();
            otRecvr->init(softspoken_ot_field_size, true);

            size_t iblt_tab_len = iblt_5h::calc_tab_len(recvr_set_size + sndr_set_size, iblt_mult_fac);
            size_t max_n_bin_probes = max_num_bin_probes(iblt_tab_len, iblt_5h::NUM_HASH_FUNCS, sndr_set_size, recvr_set_size);

            this->otCorrSendMsgs = new osuCrypto::AlignedVector<std::array<osuCrypto::block, 2>>(max_n_bin_probes + otRecvr->baseOtCount());
            this->otCorrRecvChoices = new osuCrypto::BitVector(2*max_n_bin_probes);
            this->otCorrRecvMsgs = new osuCrypto::AlignedVector<osuCrypto::block>(2*max_n_bin_probes);
            this->round_pld_els.reserve(recvr_set_size + sndr_set_size);
            this->round_recvr_owned_pld_els.reserve(recvr_set_size);
            this->iblt_remove_unique_hash_evals.reserve(iblt_tab_len);
            this->round_recvr_owned_pld_seeds.reserve(recvr_set_size);
            peeled_bm.resize(iblt_tab_len);
            sMaskedChoicesScratch.reserve(iblt_tab_len);
            rMaskedChoicesScratch.reserve(2 * iblt_tab_len);
            sMaskedMsgsScratch.reserve(iblt_tab_len);
            round_peeled_bin_idxs.reserve(iblt_tab_len);
            //this->recvr_in_set.reserve(recvr_set_size);

            delete otRecvr;
        }

        ~Receiver() {
            if (otCorrSendMsgs != nullptr) delete otCorrSendMsgs;
            if (otCorrRecvChoices != nullptr) delete otCorrRecvChoices;
            if (otCorrRecvMsgs != nullptr) delete otCorrRecvMsgs;
            if (rMaskedMsgs != nullptr) delete rMaskedMsgs;
            if (iblt != nullptr) delete iblt;
            //if (otCorrRecvMsgs128 != nullptr) delete otCorrRecvMsgs128;
            //if (otCorrSendMsgs128 != nullptr) delete otCorrSendMsgs128;
        }

        coproto::task<void> setup(coproto::Socket& sock, ItemSet& set_items);
        coproto::task<void> wan_setup(coproto::Socket& sock, ItemSet& set_items);
        //coproto::task<void> recv(coproto::Socket& sock, std::set<size_t>& q_set, iblt_5h& iblt);
        coproto::task<void> recv(coproto::Socket& sock, ItemSet& pld_els);

    };

    void msk_cnt0_choice_bits(size_t iblt_tab_len, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset);

    void msk_cnt0_choice_bits(osuCrypto::AlignedVector<size_t>& probe_idxs, 
                              size_t* cnt, 
                              osuCrypto::BitVector& maskedChoices, 
                              osuCrypto::BitVector& randChoices,
                              size_t randChoicesOffset);

};
