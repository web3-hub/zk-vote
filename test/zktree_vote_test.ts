// noinspection LossyEncoding

import { ethers } from "hardhat";
import { mimcSpongecontract } from 'circomlibjs'
import { ZKTreeVote } from "../typechain-types";
import { generateCommitment, calculateMerkleRootAndZKProof } from 'zk-merkle-tree';
import {expect} from "chai";
import EthCrypto from 'eth-crypto';

const SEED = "mimcsponge";

// the default verifier is for 20 levels, for different number of levels, you need a new verifier circuit
const TREE_LEVELS = 20;
type VoteOption = 1|2

describe("ZKTree Smart contract test", () => {

    let zktreevote: ZKTreeVote
    let votesDecodingKey: string

    before(async () => {
        // HIDE VOTES PROCEDURE:
        //
        // 1. Before voting owner create key pair (public + private). Each vote encoded off-chain with
        // public key and store on-chain
        // 2. Then voting finish, private key reveals and any one can decode votes and count results

        let { publicKey, privateKey } = EthCrypto.createIdentity()
        const votesEncodingKey = publicKey
        votesDecodingKey = privateKey

        const compressedVotesEncodingKey = EthCrypto.publicKey.compress(votesEncodingKey) // make it two times shorter


        const [deployer] = await ethers.getSigners()
        const MiMCSponge = new ethers.ContractFactory(mimcSpongecontract.abi, mimcSpongecontract.createCode(SEED, 220), deployer)
        const mimcsponge = await MiMCSponge.deploy()
        const Verifier = await ethers.getContractFactory("Verifier");
        const verifier = await Verifier.deploy();
        const ZKTreeVote = await ethers.getContractFactory("ZKTreeVote");
        zktreevote = await ZKTreeVote.deploy(
            TREE_LEVELS,
            mimcsponge.address,
            verifier.address,
            compressedVotesEncodingKey
        );
    });

    it("Test the full process", async () => {
        // noinspection JSUnusedLocalSymbols
        const [deployer, validator, ...voters] = await ethers.getSigners()
        
        await zktreevote.registerValidator(validator.address)

        // register 3 voters
        const commitment1 = await generateCommitment()
        await zktreevote.connect(validator).registerCommitment(1, commitment1.commitment)
        const commitment2 = await generateCommitment()
        await zktreevote.connect(validator).registerCommitment(2, commitment2.commitment)
        const commitment3 = await generateCommitment()
        await zktreevote.connect(validator).registerCommitment(3, commitment3.commitment)

        // get votes encryption public key
        const compressedKey = await zktreevote.votesEncodingKey();
        const votesEncodingKey = EthCrypto.publicKey.decompress(compressedKey)

        // votes
        const cd1 = await calculateMerkleRootAndZKProof(zktreevote.address, voters[0], TREE_LEVELS, commitment1, "keys/Verifier.zkey")
        const encodedVote1 = encodeVote(votesEncodingKey, 1);
        await zktreevote.connect(voters[0]).vote(encodedVote1, cd1.nullifierHash, cd1.root, cd1.proof_a, cd1.proof_b, cd1.proof_c)

        const cd2 = await calculateMerkleRootAndZKProof(zktreevote.address, voters[1], TREE_LEVELS, commitment2, "keys/Verifier.zkey")
        const encodedVote2 = encodeVote(votesEncodingKey, 1);
        expect(encodedVote1).not.equal(encodedVote2)
        await zktreevote.connect(voters[1]).vote(encodedVote2, cd2.nullifierHash, cd2.root, cd2.proof_a, cd2.proof_b, cd2.proof_c)

        const cd3 = await calculateMerkleRootAndZKProof(zktreevote.address, voters[2], TREE_LEVELS, commitment3, "keys/Verifier.zkey")
        const encodedVote3 = encodeVote(votesEncodingKey, 2);
        await zktreevote.connect(voters[2]).vote(encodedVote3, cd3.nullifierHash, cd3.root, cd3.proof_a, cd3.proof_b, cd3.proof_c)

        // REVEAL DECODING KEY
        await zktreevote.revealVotesDecodingKey(votesDecodingKey)

        // EXAMPLE OF VOTES DECODING
        const encodedVotes = await zktreevote.getVotesPage(0, await zktreevote.getVotesLength())
        const decodedVotes:VoteOption[] = await Promise.all(encodedVotes.map( async (encodedVote) => {
            // const encodedVote = EthCrypto.hex.decompress(compressedEncodedVote)
            const encoded = EthCrypto.cipher.parse(encodedVote)
            const optionWithSalt = await EthCrypto.decryptWithPrivateKey(votesDecodingKey, encoded)
            return Number(optionWithSalt.split("-")[0]) as VoteOption
        }))

        // check results
        expect(decodedVotes[0]).equal(1)
        expect(decodedVotes[1]).equal(1)
        expect(decodedVotes[2]).equal(2)
    });
});

/**
 * 1. Combine option with random salt
 * 2. Encrypt option with salt using public key
 * 3. Stringify encrypted
 *
 * @param encryptionKey
 * @param option
 */
async function encodeVote(encryptionKey: string, option: VoteOption) {
    // add salt to make brute force much more difficult. Topic to study: salt length
    const salt = EthCrypto.hash.keccak256(Math.random().toString()).substring(2, 7)
    const optionWithSalt = option.toString() + "-" + salt
    const encrypted = await EthCrypto.encryptWithPublicKey(encryptionKey, optionWithSalt)
    const encryptedStr = EthCrypto.cipher.stringify(encrypted)
    // example:
    // fbf048787a463dcbf961ca1d89a1b7f903e5d8a9b52cd97fea10bd6c180c1d9fec8b4250af5156cbe9c4584f0fd411b4412a6c73453d5f0a0ecfd0f36144a08736be1c891d9d7e512f46e8c0ee848d20d335e00c6effce13c9a5ed7975cbe1e481

    // noinspection JSUnusedLocalSymbols
    const utf16 = EthCrypto.hex.compress(encryptedStr)
    // example:
    // °踷眝ꄁ꿼柎?톈⌃䨳呑祥却䣐墺莎㎭㳚뷅曮꧳ᩈԟ虏ꯖ⵫⪡䴗儘쀪ਚꫨ繻ື?ﮏ≦罱ᴟ앳轻╚笶ެ뤍௝
    // cannot save UTF16 to Smart Contract

    // noinspection JSUnusedLocalSymbols
    const base64 = EthCrypto.hex.compress(encryptedStr, true)
    // example:
    // sI43dx2hAa/8Z87cwNGIIwNKM/XcVFH6GlN0SNBYuoOOM6082r3FZu6p8xpIBR+GT6vW66AtayqhTRdRGMAqChqq6H57Drfe6vuPImZ/cR0fxXOPeyVa7Fd7NgesuQ0L3Q==
    return encryptedStr
}