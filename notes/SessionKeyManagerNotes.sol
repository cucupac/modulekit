// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* solhint-disable function-max-lines*/
/* solhint-disable ordering*/

import { ERC7579ValidatorBase } from "modulekit/modules/ERC7579ValidatorBase.sol";
import { UserOperation, UserOperationLib } from "modulekit/external/ERC4337.sol";
import { IERC7579Execution } from "modulekit/Accounts.sol";
import { IERC1271 } from "modulekit/interfaces/IERC1271.sol";
import { ISessionValidationModule } from "./ISessionValidationModule.sol";
import { SessionData, SessionKeyManagerLib } from "./SessionKeyManagerLib.sol";
import { ISessionKeyManager } from "./ISessionKeyManager.sol";
import {
    ACCOUNT_EXEC_TYPE, ERC7579ValidatorLib
} from "modulekit/modules/utils/ERC7579ValidatorLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

contract SessionKeyManager is ERC7579ValidatorBase {
    using UserOperationLib for UserOperation;
    using ERC7579ValidatorLib for UserOperation;
    using ERC7579ValidatorLib for bytes;
    using SessionKeyManagerLib for SessionData;
    using SessionKeyManagerLib for bytes32;

    event SessionCreated(address indexed sa, bytes32 indexed sessionDataDigest, SessionData data);
    event SessionDisabled(address indexed sa, bytes32 indexed sessionDataDigest);
    // For a given Session Data Digest and Smart Account, stores
    // - the corresponding Session Data if the Session is enabled
    // - nothing otherwise

    mapping(bytes32 sessionDataDigest => mapping(address sa => SessionData data)) internal
        _enabledSessionsData;

    function disableSession(bytes32 _sessionDigest) external {
        delete _enabledSessionsData[_sessionDigest][msg.sender];
        emit SessionDisabled(msg.sender, _sessionDigest);
    }

    /*
    struct SessionData {
        uint48 validUntil;
        uint48 validAfter;
        ISessionValidationModule sessionValidationModule;
        bytes sessionKeyData;
    }

    sessionKeyData is:
    struct ScopedAccess {
        address sessionKeySigner;
        address onlyToken;
        uint256 maxAmount;
    }

    sessionKeyData includes the signer.
    backend proudces this object that EOA signs off on.
    --> the signer got here by the EOA signing off on it.

    It's also passed into the validateSessionParams, where it is returned.
    QUESTION: How it is passed in? --> It's passed in directly from this mapping.

    More specifically, 
    This contract:
    1. a signture is passed in from entry point
    2. the digest is extracted and used to query the mapping for the session data object 
    3. the session data object has session key data, which is scoped access
    4. scoped access has the key signer
    5. the session data object is passed to the actual module to verify session params

    Actual module: veries params in user app are within permission bounds
    1. params are in correct form
    2. target contract is correct (this contract will be doing the thing)
    3. call value is 0
    4. function call is restricted
    5. provided access object stored in state for the smart account is of correct form
    6. params match the access object
    7. return the signer

    This contract:
    1. That signer that ultimately came from this contract (that the user signed off on) is used to
    verify the signature in the userOp
        valid if:
            A. the signature signed the digest
            B. the signer produced the signature
    2. If valid, and passed up to this point, we can asset the following:
        A. the params in the user op are within permission bounds
    B. the signer that EOA approved signed the userOp and is therefore the one doing the action that
    EOA approved

    QUESTION: what if a faulty signer is passed in with valid permissions?
    ANSWER: it would fail the signature step as the signer used for the signature ultimately comes
    from the mapping that EOA approved

    QUESTION: what if an invalid digest is passed in? 
    ANSWER: it would fail the signature step

    QUESTION: what if a valid signature is passed in, but not within permission bounds?
    ANSWER: it would fail the validateSessionParams step

    QUESTION: what if it fails?
    ANSWER: since this is in a call-chain started from an entry point --> smart account --> this
    contract, it would fail and the transaction would not go through.

    QUESTION: what if the session data is not in the mapping?
    ANSWER: the validateSessionParams would fail as it mandates that access of a correct form
    ANSWER: this would be indicative of there being a faulty digest or the EOA never approving
    ANSWER: given that, there would be no signature to validate, causing a revert.

    QUESTION: what if everything works?
    ANSWER: then the entrypoint will ultimately execute the to, value, and calldata passed in will
    be execute.
    that calldata and target will necessarily be the executor module, which in turn will execute the
    on the smart account's behalf.

    QUESTION: Okay, so this approach works, but is it possible to "go around this"? 
    */

    // NOTE: This function is called from that outside world. It therefore must know the "Scope"
    //       sessionKeyData IS the scope.
    // QUESTION: Why are there not strict permissions on who can call this?
    // ANSWER: Becuase it users msg.sender --> they would pay the gas
    //         The msg.sender in this case would be the smart account
    //         This means that you'd go throught the entry point and then through the smart account
    // to call this.
    function enableSession(SessionData calldata sessionData) external {
        bytes32 sessionDataDigest_ = sessionData.digest();
        _enabledSessionsData[sessionDataDigest_][msg.sender] = sessionData;
        emit SessionCreated(msg.sender, sessionDataDigest_, sessionData);
    }

    function digest(SessionData calldata sessionData) external pure returns (bytes32) {
        return sessionData.digest();
    }

    function getSessionData(
        address smartAccount,
        bytes32 sessionDigest
    )
        external
        view
        returns (SessionData memory data)
    {
        data = _enabledSessionsData[sessionDigest][smartAccount];
    }

    // NOTE: THIS IS CALLED FROM THE OUTSIDE WORLD
    // NOTE: IT SIMPLY RETURNS THE VALIDATION DATA
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        virtual
        override
        returns (ValidationData vd)
    {
        ACCOUNT_EXEC_TYPE accountExecType = userOp.callData.decodeExecType();

        if (ACCOUNT_EXEC_TYPE.EXEC_SINGLE == accountExecType) {
            return _validateSingleExec(userOp, userOpHash);
        } else if (ACCOUNT_EXEC_TYPE.EXEC_BATCH == accountExecType) {
            return _validateBatchedExec(userOp, userOpHash);
        } else {
            return _validatorError();
        }
    }

    function _validateSingleExec(
        UserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        returns (ValidationData vd)
    {
        // NOTE: 1. GET SMART ACCOUNT
        address smartAccount = userOp.getSender();

        // NOTE: 2. EXTRACT SESSION KEY DATA DIGEST AND SIGNATURE FROM USEROP.SIGNATURE
        (bytes32 sessionKeyDataDigest, bytes calldata sessionKeySignature) =
            SessionKeyManagerLib.decodeSignatureSingle(userOp.signature);

        // NOTE: 3. LOOK AT MAPPING FOR SESSION KEY DATA DIGEST AND SMART ACCOUNT: IT GIVES SESSION
        // DATA
        // NOTE: Keep in mind, we're in the call chain of what originally was sent to the entry
        // point by a bundler
        //       If it was valid, then there would indeed be sessionData returned. If invalid, there
        // would not be session data returned.
        // QUESTION: What if it's invalid (and therefore no session data)
        SessionData storage sessionData = _enabledSessionsData[sessionKeyDataDigest][smartAccount];

        // NOTE: IT LOOKS LIKE THIS:
        /*
        struct SessionData {
            uint48 validUntil;
            uint48 validAfter;
            ISessionValidationModule sessionValidationModule;
            bytes sessionKeyData;
        }
        */

        // NOTE: 4. EXTRACT TO, VALUE, AND CALLDATA FROM USEROP.CALLDATA
        (address to, uint256 value, bytes calldata callData) =
            ERC7579ValidatorLib.decodeCalldataSingle(userOp.callData);

        // NOTE: VALIDATE THE PARAMS (USING SESSION DATA AND SESSION KEY SIGNATURE)
        // NOTE: The session key signature is the signature of from the session key on the backend
        //       BOX HAS CORRECT CONTENTS.
        (address signer, uint48 validUntil, uint48 validAfter) =
            _validateWithSessionKey(to, value, callData, sessionKeySignature, sessionData);

        // NOTE: VALIDATE THE SIGNATURE (EC RECOVER OR EIP1271 FOR CONTRACTS)
        //       SENDER IS CORRECT.
        // Give it:
        /*
        1. what was signed (digest)
        2. who signed it
        3. the signature

        valid if:
        1. the signature signed the data
        2. the signer produced the signature

        QUESTION: That's fine, but how to know that the signer even has the rights? Is this done in
        enableSession?
        */
        bool isValid = SignatureCheckerLib.isValidSignatureNowCalldata(
            signer, sessionKeyDataDigest, sessionKeySignature
        );

        if (!isValid) return _validatorError();

        // THIS FUNCTION IS CALLED FROM ERC7579ValidatorBase (INHERITED)
        vd = _packValidationData(!isValid, validUntil, validAfter);
    }

    function _validateBatchedExec(
        UserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        returns (ValidationData vd)
    {
        address smartAccount = userOp.getSender();

        // do we need to check userOpHash
        (bytes32[] calldata sessionKeyDataDigests, bytes[] calldata sessionKeySignatures) =
            SessionKeyManagerLib.decodeSignatureBatch(userOp.signature);

        // get ERC7579 Execution struct array from callData
        IERC7579Execution.Execution[] calldata execs =
            ERC7579ValidatorLib.decodeCalldataBatch(userOp.callData);

        uint256 length = sessionKeySignatures.length;
        if (execs.length != length) {
            return _validatorError();
        }

        uint48 maxValidUntil;
        uint48 minValidAfter;
        for (uint256 i; i < length; i++) {
            // ----- Cached Data -----
            IERC7579Execution.Execution calldata execution = execs[i];
            bytes32 sessionKeyDataDigest = sessionKeyDataDigests[i];
            bytes calldata sessionKeySignature = sessionKeySignatures[i];
            // ----------
            SessionData storage sessionData =
                _enabledSessionsData[sessionKeyDataDigest][smartAccount];
            (address signer, uint48 validUntil, uint48 validAfter) = _validateWithSessionKey(
                execution.target,
                execution.value,
                execution.callData,
                sessionKeySignature,
                sessionData
            );

            bool isValid = SignatureCheckerLib.isValidSignatureNowCalldata(
                signer, sessionKeyDataDigest, sessionKeySignature
            );
            if (!isValid) return _validatorError();
            if (maxValidUntil < validUntil) {
                maxValidUntil = validUntil;
            }
            if (minValidAfter > validAfter) {
                minValidAfter = validAfter;
            }
        }
        return _packValidationData(false, maxValidUntil, minValidAfter);
    }

    function _validateWithSessionKey(
        address to,
        uint256 value,
        bytes calldata callData,
        bytes calldata sessionKeySignature,
        SessionData storage sessionData
    )
        internal
        returns (address signer, uint48 validUntil, uint48 validAfter)
    {
        ISessionValidationModule sessionValidationModule = sessionData.sessionValidationModule;

        // NOTE: Here, the first link is established with the executor contract
        signer = sessionValidationModule.validateSessionParams({
            to: to,
            value: value,
            callData: callData,
            sessionKeyData: sessionData.sessionKeyData,
            callSpecificData: sessionKeySignature
        });

        validUntil = sessionData.validUntil;
        validAfter = sessionData.validAfter;
    }

    function _validatorError() internal pure returns (ValidationData vd) {
        return _packValidationData(true, 0, 0);
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        override
        returns (bytes4)
    { }

    function name() external pure virtual override returns (string memory) {
        return "SessionKeyManager";
    }

    function version() external pure virtual override returns (string memory) {
        return "0.0.1";
    }

    function isModuleType(uint256 _type) external pure virtual override returns (bool) {
        return _type == TYPE_VALIDATOR;
    }

    function onInstall(bytes calldata data) external override { }

    function onUninstall(bytes calldata data) external override { }
}
