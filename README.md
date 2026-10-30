# ERC-draft-
ERC draft: Independent Simulation Result for (STVA)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library SimulationResultLib {
    struct SimulationResult {
        bool success;
        uint256 gasUsed;
        bytes returnData;
        bytes stateDiffCanonical;
        bytes logsCanonical;
        bytes32 snapshotId;
        string derivedSummary;
        uint256 chainId;
    }

    function build(
        bool success_,
        uint256 gasUsed_,
        bytes memory returnData_,
        bytes memory stateDiffCanonical_,
        bytes memory logsCanonical_,
        bytes32 snapshotId_,
        string memory derivedSummary_,
        uint256 chainId_
    ) internal pure returns (SimulationResult memory) {
        return SimulationResult({
            success: success_,
            gasUsed: gasUsed_,
            returnData: returnData_,
            stateDiffCanonical: stateDiffCanonical_,
            logsCanonical: logsCanonical_,
            snapshotId: snapshotId_,
            derivedSummary: derivedSummary_,
            chainId: chainId_
        });
    }

    function pureHash(SimulationResult memory result) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                result.success,
                result.gasUsed,
                keccak256(result.returnData),
                keccak256(result.stateDiffCanonical),
                keccak256(result.logsCanonical),
                result.snapshotId,
                keccak256(bytes(result.derivedSummary)),
                result.chainId
            )
        );
    }

    function hashSimulationResult(
        SimulationResult memory result,
        bytes32 domainSeparator
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domainSeparator, pureHash(result)));
    }
}

contract SimulationResultRegistry {
    using SimulationResultLib for SimulationResultLib.SimulationResult;

    bytes32 public constant DOMAIN_SEPARATOR = keccak256("SimulationResultRegistry");

    mapping(bytes32 => mapping(address => bool)) public hasAttestation;
    mapping(bytes32 => uint48) private _committedAt;

    function attest(
        SimulationResultLib.SimulationResult memory result,
        bytes memory sig
    ) external {
        bytes32 resultHash = result.pureHash();
        bytes32 digest = result.hashSimulationResult(DOMAIN_SEPARATOR);

        // Strong Ethereum-signature verification:
        address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(digest), sig);

        require(signer == msg.sender, "SimulationResultRegistry: invalid signer");
        require(!hasAttestation[resultHash][signer], "SimulationResultRegistry: already attested");

        hasAttestation[resultHash][signer] = true;

        if (_committedAt[resultHash] == 0) {
            _committedAt[resultHash] = uint48(block.timestamp);
        }
    }

    function committedAt(bytes32 resultHash) external view returns (uint48) {
        return _committedAt[resultHash];
    }
}
