/*
 * Copyright 2019 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.pantheon.ethereum.privacy;

import tech.pegasys.pantheon.ethereum.core.Transaction;

public class PrivateTransactionHandler {

  public Transaction handle(final PrivateTransaction privateTransaction) {
    //    send request out to Enclave Client and get encrypted transaction hash (enclave address)
    //
    //    Fire off to Privacy Pre-compile Service
    return new Transaction(
        privateTransaction.getNonce(),
        privateTransaction.getGasPrice(),
        privateTransaction.getGasLimit(),
        privateTransaction.getTo(),
        privateTransaction.getValue(),
        privateTransaction.getSignature(),
        privateTransaction.getPayload(),
        privateTransaction.sender,
        privateTransaction.getChainId().getAsInt());
  }
}
