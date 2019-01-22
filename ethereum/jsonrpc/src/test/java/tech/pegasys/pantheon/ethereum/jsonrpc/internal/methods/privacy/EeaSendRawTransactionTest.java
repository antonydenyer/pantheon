/*
 * Copyright 2018 ConsenSys AG.
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
package tech.pegasys.pantheon.ethereum.jsonrpc.internal.methods.privacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import tech.pegasys.pantheon.ethereum.core.Transaction;
import tech.pegasys.pantheon.ethereum.core.TransactionPool;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.JsonRpcRequest;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.parameters.JsonRpcParameter;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcError;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcErrorResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcSuccessResponse;
import tech.pegasys.pantheon.ethereum.mainnet.TransactionValidator.TransactionInvalidReason;
import tech.pegasys.pantheon.ethereum.mainnet.ValidationResult;
import tech.pegasys.pantheon.ethereum.privacy.PrivateTransactionHandler;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class EeaSendRawTransactionTest {

  private static final String VALID_PRIVATE_TRANSACTION_RLP =
      "0xf90113800182520894095e7baea6a6c7c4c2dfeb977efac326af552d87"
          + "a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          + "ffff801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d"
          + "495a36649353a01fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab94"
          + "9f53faa07bd2c804ac41316156744d784c4355486d425648586f5a7a7a4267"
          + "5062572f776a3561784470573958386c393153476f3df85aac41316156744d"
          + "784c4355486d425648586f5a7a7a42675062572f776a356178447057395838"
          + "6c393153476f3dac4b6f32625671442b6e4e6c4e594c35454537793349644f"
          + "6e766966746a69697a706a52742b4854754642733d8a726573747269637465"
          + "64";

  @Mock private TransactionPool transactionPool;

  @Mock private JsonRpcParameter parameter;

  @Mock private EeaSendRawTransaction method;

  @Mock private PrivateTransactionHandler privateTxHandler;

  @Before
  public void before() {
    method = new EeaSendRawTransaction(privateTxHandler, transactionPool, parameter);
  }

  @Test
  public void requestIsMissingParameter() {
    final JsonRpcRequest request =
        new JsonRpcRequest("2.0", "eea_sendRawTransaction", new String[] {});

    final JsonRpcResponse expectedResponse =
        new JsonRpcErrorResponse(request.getId(), JsonRpcError.INVALID_PARAMS);

    final JsonRpcResponse actualResponse = method.response(request);

    assertThat(actualResponse).isEqualToComparingFieldByField(expectedResponse);
  }

  @Test
  public void invalidTransactionRlpDecoding() {
    final String rawTransaction = "0x00";
    when(parameter.required(any(Object[].class), anyInt(), any())).thenReturn(rawTransaction);

    final JsonRpcRequest request =
        new JsonRpcRequest("2.0", "eea_sendRawTransaction", new String[] {rawTransaction});

    final JsonRpcResponse expectedResponse =
        new JsonRpcErrorResponse(request.getId(), JsonRpcError.INVALID_PARAMS);

    final JsonRpcResponse actualResponse = method.response(request);

    assertThat(actualResponse).isEqualToComparingFieldByField(expectedResponse);
  }

  @Test
  public void validTransactionIsSentToTransactionPool() {
    when(parameter.required(any(Object[].class), anyInt(), any()))
        .thenReturn(VALID_PRIVATE_TRANSACTION_RLP);
    when(transactionPool.addLocalTransaction(any(Transaction.class)))
        .thenReturn(ValidationResult.valid());

    final JsonRpcRequest request =
        new JsonRpcRequest(
            "2.0", "eea_sendRawTransaction", new String[] {VALID_PRIVATE_TRANSACTION_RLP});

    final JsonRpcResponse expectedResponse =
        new JsonRpcSuccessResponse(
            request.getId(), "0xbaabcc1bd699e7378451e4ce5969edb9bdcae76cb79bdacae793525c31e423c7");

    final JsonRpcResponse actualResponse = method.response(request);

    assertThat(actualResponse).isEqualToComparingFieldByField(expectedResponse);
    verify(transactionPool).addLocalTransaction(any(Transaction.class));
  }

  @Test
  public void transactionWithNonceBelowAccountNonceIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.NONCE_TOO_LOW, JsonRpcError.NONCE_TOO_LOW);
  }

  @Test
  public void transactionWithNonceAboveAccountNonceIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.INCORRECT_NONCE, JsonRpcError.INCORRECT_NONCE);
  }

  @Test
  public void transactionWithInvalidSignatureIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.INVALID_SIGNATURE, JsonRpcError.INVALID_TRANSACTION_SIGNATURE);
  }

  @Test
  public void transactionWithIntrinsicGasExceedingGasLimitIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.INTRINSIC_GAS_EXCEEDS_GAS_LIMIT,
        JsonRpcError.INTRINSIC_GAS_EXCEEDS_LIMIT);
  }

  @Test
  public void transactionWithUpfrontGasExceedingAccountBalanceIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.UPFRONT_COST_EXCEEDS_BALANCE,
        JsonRpcError.TRANSACTION_UPFRONT_COST_EXCEEDS_BALANCE);
  }

  @Test
  public void transactionWithGasLimitExceedingBlockGasLimitIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.EXCEEDS_BLOCK_GAS_LIMIT, JsonRpcError.EXCEEDS_BLOCK_GAS_LIMIT);
  }

  @Test
  public void transactionWithNotWhitelistedSenderAccountIsRejected() {
    verifyErrorForInvalidTransaction(
        TransactionInvalidReason.TX_SENDER_NOT_AUTHORIZED, JsonRpcError.TX_SENDER_NOT_AUTHORIZED);
  }

  private void verifyErrorForInvalidTransaction(
      final TransactionInvalidReason transactionInvalidReason, final JsonRpcError expectedError) {
    when(parameter.required(any(Object[].class), anyInt(), any()))
        .thenReturn(VALID_PRIVATE_TRANSACTION_RLP);
    when(transactionPool.addLocalTransaction(any(Transaction.class)))
        .thenReturn(ValidationResult.invalid(transactionInvalidReason));

    final JsonRpcRequest request =
        new JsonRpcRequest(
            "2.0", "eea_sendRawTransaction", new String[] {VALID_PRIVATE_TRANSACTION_RLP});

    final JsonRpcResponse expectedResponse =
        new JsonRpcErrorResponse(request.getId(), expectedError);

    final JsonRpcResponse actualResponse = method.response(request);

    assertThat(actualResponse).isEqualToComparingFieldByField(expectedResponse);
    verify(transactionPool).addLocalTransaction(any(Transaction.class));
  }

  @Test
  public void getMethodReturnsExpectedName() {
    assertThat(method.getName()).matches("eea_sendRawTransaction");
  }
}
