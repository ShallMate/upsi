
// Copyright 2025 Guowei Ling
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "aPSI.h"

#include <apsi/network/stream_channel.h>
#include <apsi/sender.h>

#include "apsi/oprf/oprf_receiver.h"
#include "apsi/receiver.h"

#include "yacl/base/int128.h"

std::vector<uint128_t> APSI::APsiRun(std::vector<uint128_t>& items) {
  std::vector<std::string> raw_receiver_items_str = ItemsToStr(items);
  // We need to convert the strings to Item objects
  std::vector<apsi::Item> receiver_items(raw_receiver_items_str.begin(),
                                         raw_receiver_items_str.end());

  // We need to convert the strings to Item objects

  // The first step is to obtain OPRF values for these items, so we need to
  // create an oprf::OPRFReceiver object and use it to create an OPRF request
  apsi::oprf::OPRFReceiver oprf_receiver =
      apsi::receiver::Receiver::CreateOPRFReceiver(receiver_items);
  apsi::Request request =
      apsi::receiver::Receiver::CreateOPRFRequest(oprf_receiver);

  // Send the OPRF request on our communication channel (note the need to
  // std::move it)
  channel_->send(std::move(request));

  // The Sender must receive the OPRF request (need to convert it to OPRFRequest
  // type)
  apsi::Request received_request =
      channel_->receive_operation(sender_db->get_seal_context());
  apsi::OPRFRequest received_oprf_request =
      apsi::to_oprf_request(std::move(received_request));

  // Process the OPRF request and send a response back to the Receiver
  apsi::sender::Sender::RunOPRF(received_oprf_request,
                                sender_db->get_oprf_key(), *channel_);

  // The Receiver can now get the OPRF response from the communication channel.
  // We need to extract the OPRF hashes from the response.
  apsi::Response response = channel_->receive_response();
  apsi::OPRFResponse oprf_response = apsi::to_oprf_response(response);
  std::pair<std::vector<apsi::HashedItem>, std::vector<apsi::LabelKey>>
      receiver_oprf_items =
          apsi::receiver::Receiver::ExtractHashes(oprf_response, oprf_receiver);

  // With the OPRF hashed Receiver's items, we are ready to create a PSI query.
  // First though, we need to create our Receiver object (assume here the
  // Receiver knows the PSI parameters). We need to keep the
  // IndexTranslationTable object that Receiver::create_query returns.
  apsi::receiver::Receiver receiver(*params_);
  std::pair<apsi::Request, apsi::receiver::IndexTranslationTable> query_data =
      receiver.create_query(receiver_oprf_items.first);
  apsi::receiver::IndexTranslationTable itt = query_data.second;
  request = std::move(query_data.first);

  // Now we are ready to send the PSI query request on our communication channel
  channel_->send(std::move(request));

  // The Sender will then receive the PSI query request
  received_request = channel_->receive_operation(sender_db->get_seal_context());
  apsi::QueryRequest received_query_request =
      apsi::to_query_request(received_request);

  // We need to extract the PSI query first
  apsi::sender::Query query(std::move(received_query_request), sender_db);

  // Process the PSI query request and send the response back to the Receiver
  apsi::sender::Sender::RunQuery(query, *channel_);

  // The Receiver then receives a QueryResponse object on the channel
  response = channel_->receive_response();
  apsi::QueryResponse query_response = apsi::to_query_response(response);

  // The actual result data is communicated separately; the query response only
  // contains the number of ResultPart objects we expect to receive.
  uint32_t result_part_count = query_response->package_count;

  // Now loop to receive all of the ResultParts
  std::vector<apsi::ResultPart> result_parts;
  while ((result_part_count--) != 0U) {
    apsi::ResultPart result_part =
        channel_->receive_result(receiver.get_seal_context());
    result_parts.push_back(std::move(result_part));
  }

  std::vector<apsi::receiver::MatchRecord> results =
      receiver.process_result(receiver_oprf_items.second, itt, result_parts);
  std::vector<uint128_t> intersection;
  for (size_t i = 0; i < items.size(); i++) {
    if (results[i].found) {
      intersection.push_back(items[i]);
    }
  }
  return intersection;
}

/*
std::vector<uint128_t> APSI::PreCom(std::vector<uint128_t>& items){

    std::vector<std::string> raw_receiver_items_str = ItemsToStr(items);
    // We need to convert the strings to Item objects
    std::vector<apsi::Item> receiver_items(raw_receiver_items_str.begin(),
raw_receiver_items_str.end());

     // We need to convert the strings to Item objects


    // The first step is to obtain OPRF values for these items, so we need to
    // create an oprf::OPRFReceiver object and use it to create an OPRF request
    oprf::OPRFReceiver oprf_receiver =
receiver::Receiver::CreateOPRFReceiver(receiver_items); Request request =
receiver::Receiver::CreateOPRFRequest(oprf_receiver);

    // Send the OPRF request on our communication channel (note the need to
std::move it) channel_->send(std::move(request));

    // The Sender must receive the OPRF request (need to convert it to
OPRFRequest type) Request received_request =
channel_->receive_operation(sender_db->get_seal_context()); OPRFRequest
received_oprf_request = to_oprf_request(std::move(received_request));

    // Process the OPRF request and send a response back to the Receiver
    sender::Sender::RunOPRF(received_oprf_request, sender_db->get_oprf_key(),
*channel_);

    // The Receiver can now get the OPRF response from the communication
channel.
    // We need to extract the OPRF hashes from the response.
    Response response = channel_->receive_response();
    OPRFResponse oprf_response = to_oprf_response(response);
    std::pair<std::vector<HashedItem>, std::vector<LabelKey>>
receiver_oprf_items = receiver::Receiver::ExtractHashes( oprf_response,
        oprf_receiver
    );


    return intersection;
}


// If the Receiver wants to run a query, and the Sender has already inserted the
items std::vector<uint128_t> APSI::RunQuery(sender::Query query,const
std::pair<std::vector<HashedItem>, std::vector<LabelKey>>&
receiver_oprf_items,std::vector<uint128_t>& items){ receiver::Receiver
receiver(*params_); std::pair<Request, receiver::IndexTranslationTable>
query_data = receiver.create_query(receiver_oprf_items.first);
    receiver::IndexTranslationTable itt = query_data.second;
    request = std::move(query_data.first);

    // Now we are ready to send the PSI query request on our communication
channel channel_->send(std::move(request));

    // The Sender will then receive the PSI query request
    received_request =
channel_->receive_operation(sender_db->get_seal_context()); QueryRequest
received_query_request = to_query_request(received_request);

    // We need to extract the PSI query first
    sender::Query query(std::move(received_query_request), sender_db);

    // Process the PSI query request and send the response back to the Receiver
    sender::Sender::RunQuery(query, *channel_);

    // The Receiver then receives a QueryResponse object on the channel
    response = channel_->receive_response();
    QueryResponse query_response = to_query_response(response);

    // The actual result data is communicated separately; the query response
only
    // contains the number of ResultPart objects we expect to receive.
    uint32_t result_part_count = query_response->package_count;

    // Now loop to receive all of the ResultParts
    std::vector<ResultPart> result_parts;
    while ((result_part_count--) != 0U) {
        ResultPart result_part =
channel_->receive_result(receiver.get_seal_context());
        result_parts.push_back(std::move(result_part));
    }

    std::vector<apsi::receiver::MatchRecord> results
        = receiver.process_result(receiver_oprf_items.second, itt,
result_parts); std::vector<uint128_t> intersection; for (size_t i = 0; i <
items.size(); i++) { if (results[i].found) { intersection.push_back(items[i]);
        }
    }
    return intersection;
}
*/