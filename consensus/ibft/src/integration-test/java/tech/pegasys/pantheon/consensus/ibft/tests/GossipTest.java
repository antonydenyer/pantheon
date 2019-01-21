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
package tech.pegasys.pantheon.consensus.ibft.tests;

import static java.util.Collections.emptyList;
import static tech.pegasys.pantheon.consensus.ibft.support.MessageReceptionHelpers.assertPeersReceivedMessages;
import static tech.pegasys.pantheon.consensus.ibft.support.MessageReceptionHelpers.assertPeersReceivedNoMessages;

import tech.pegasys.pantheon.consensus.ibft.ConsensusRoundIdentifier;
import tech.pegasys.pantheon.consensus.ibft.IbftBlockHashing;
import tech.pegasys.pantheon.consensus.ibft.IbftExtraData;
import tech.pegasys.pantheon.consensus.ibft.IbftHelpers;
import tech.pegasys.pantheon.consensus.ibft.ibftevent.NewChainHead;
import tech.pegasys.pantheon.consensus.ibft.messagedata.ProposalMessageData;
import tech.pegasys.pantheon.consensus.ibft.payload.CommitPayload;
import tech.pegasys.pantheon.consensus.ibft.payload.MessageFactory;
import tech.pegasys.pantheon.consensus.ibft.payload.NewRoundPayload;
import tech.pegasys.pantheon.consensus.ibft.payload.PreparePayload;
import tech.pegasys.pantheon.consensus.ibft.payload.ProposalPayload;
import tech.pegasys.pantheon.consensus.ibft.payload.RoundChangeCertificate;
import tech.pegasys.pantheon.consensus.ibft.payload.RoundChangePayload;
import tech.pegasys.pantheon.consensus.ibft.payload.SignedData;
import tech.pegasys.pantheon.consensus.ibft.support.RoundSpecificNodeRoles;
import tech.pegasys.pantheon.consensus.ibft.support.TestContext;
import tech.pegasys.pantheon.consensus.ibft.support.TestContextFactory;
import tech.pegasys.pantheon.consensus.ibft.support.ValidatorPeer;
import tech.pegasys.pantheon.crypto.SECP256K1;
import tech.pegasys.pantheon.crypto.SECP256K1.KeyPair;
import tech.pegasys.pantheon.crypto.SECP256K1.Signature;
import tech.pegasys.pantheon.ethereum.core.Block;
import tech.pegasys.pantheon.ethereum.core.Hash;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;

public class GossipTest {
  private final long blockTimeStamp = 100;
  private final Clock fixedClock =
      Clock.fixed(Instant.ofEpochSecond(blockTimeStamp), ZoneId.systemDefault());

  private final int NETWORK_SIZE = 5;

  private final TestContext context =
      TestContextFactory.createTestEnvironmentWithGossip(NETWORK_SIZE, 0, fixedClock);

  private final ConsensusRoundIdentifier roundId = new ConsensusRoundIdentifier(1, 0);
  private final RoundSpecificNodeRoles roles = context.getRoundSpecificRoles(roundId);
  private Block block;
  private ValidatorPeer gossiper;
  private MessageFactory msgFactory;
  private SignedData<ProposalPayload> proposal;

  @Before
  public void setup() {
    context.getController().start();
    block = context.createBlockForProposalFromChainHead(roundId.getRoundNumber(), 30);
    gossiper = roles.getProposer();
    msgFactory = gossiper.getMessageFactory();

    proposal = msgFactory.createSignedProposalPayload(roundId, block);
  }

  @Test
  public void gossipMessagesToPeers() {
    gossiper.injectProposal(roundId, block);
    assertPeersReceivedMessages(roles.getNonProposingPeers(), proposal);

    gossiper.injectPrepare(roundId, block.getHash());
    final SignedData<PreparePayload> prepare =
        msgFactory.createSignedPreparePayload(roundId, block.getHash());
    assertPeersReceivedMessages(roles.getNonProposingPeers(), prepare);

    gossiper.injectCommit(roundId, block.getHash());
    final IbftExtraData extraData = IbftExtraData.decode(block.getHeader().getExtraData());
    final Hash commitHash =
        IbftBlockHashing.calculateDataHashForCommittedSeal(block.getHeader(), extraData);
    final Signature commitSeal = SECP256K1.sign(commitHash, gossiper.getNodeKeyPair());
    final SignedData<CommitPayload> commit =
        msgFactory.createSignedCommitPayload(roundId, block.getHash(), commitSeal);
    assertPeersReceivedMessages(roles.getNonProposingPeers(), commit);

    final SignedData<RoundChangePayload> roundChange =
        msgFactory.createSignedRoundChangePayload(roundId, Optional.empty());
    final RoundChangeCertificate roundChangeCert =
        new RoundChangeCertificate(Collections.singleton(roundChange));
    final SignedData<NewRoundPayload> newRound =
        msgFactory.createSignedNewRoundPayload(roundId, roundChangeCert, proposal);
    gossiper.injectNewRound(roundId, roundChangeCert, proposal);
    assertPeersReceivedMessages(roles.getNonProposingPeers(), newRound);

    gossiper.injectRoundChange(roundId, Optional.empty());
    assertPeersReceivedMessages(roles.getNonProposingPeers(), roundChange);
  }

  @Test
  public void messageIsOnlyGossipedOnce() {
    gossiper.injectProposal(roundId, block);
    assertPeersReceivedMessages(roles.getNonProposingPeers(), proposal);

    gossiper.injectProposal(roundId, block);
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());

    gossiper.injectProposal(roundId, block);
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());
  }

  @Test
  public void messageWithUnknownValidatorIsNotGossiped() {
    final KeyPair unknownKeyPair = KeyPair.generate();
    final MessageFactory unknownMsgFactory = new MessageFactory(unknownKeyPair);
    final SignedData<ProposalPayload> unknownProposal =
        unknownMsgFactory.createSignedProposalPayload(roundId, block);

    gossiper.injectMessage(ProposalMessageData.create(unknownProposal));
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());
  }

  @Test
  public void messageIsNotGossipedToSenderOrCreator() {
    final ValidatorPeer msgCreator = roles.getNonProposingPeer(0);
    final MessageFactory peerMsgFactory = msgCreator.getMessageFactory();
    final SignedData<ProposalPayload> proposalFromPeer =
        peerMsgFactory.createSignedProposalPayload(roundId, block);

    gossiper.injectMessage(ProposalMessageData.create(proposalFromPeer));

    final List<ValidatorPeer> validators = new ArrayList<>(roles.getNonProposingPeers());
    validators.remove(msgCreator);
    assertPeersReceivedMessages(validators, proposalFromPeer);
    assertPeersReceivedNoMessages(ImmutableList.of(roles.getProposer(), msgCreator));
  }

  @Test
  public void futureMessageIsNotGossipedImmediately() {
    ConsensusRoundIdentifier futureRoundId = new ConsensusRoundIdentifier(2, 0);
    msgFactory.createSignedProposalPayload(futureRoundId, block);

    gossiper.injectProposal(futureRoundId, block);
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());
  }

  @Test
  public void previousHeightMessageIsNotGossiped() {
    ConsensusRoundIdentifier futureRoundId = new ConsensusRoundIdentifier(0, 0);
    msgFactory.createSignedProposalPayload(futureRoundId, block);

    gossiper.injectProposal(futureRoundId, block);
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());
  }

  @Test
  public void futureMessageGetGossipedLater() {
    final Block signedCurrentHeightBlock =
        IbftHelpers.createSealedBlock(
            block,
            roles
                .getAllPeers()
                .stream()
                .map(peer -> peer.getBlockSignature(block.getHash()))
                .collect(Collectors.toList()));

    ConsensusRoundIdentifier futureRoundId = new ConsensusRoundIdentifier(2, 0);
    SignedData<ProposalPayload> futureProposal =
        msgFactory.createSignedProposalPayload(futureRoundId, block);

    gossiper.injectProposal(futureRoundId, block);
    assertPeersReceivedNoMessages(roles.getNonProposingPeers());

    // add block to chain so we can move to next block height
    context.getBlockchain().appendBlock(signedCurrentHeightBlock, emptyList());
    context
        .getController()
        .handleNewBlockEvent(new NewChainHead(signedCurrentHeightBlock.getHeader()));

    assertPeersReceivedMessages(roles.getNonProposingPeers(), futureProposal);
  }
}