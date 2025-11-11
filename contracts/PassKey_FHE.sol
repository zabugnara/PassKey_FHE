pragma solidity ^0.8.24;

import { FHE, euint32, externalEuint32 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract PassKeyFHE is ZamaEthereumConfig {
    struct PasswordEntry {
        string serviceName;
        euint32 encryptedPassword;
        uint256 lastUpdated;
        address owner;
        bool isVerified;
        uint32 decryptedPassword;
    }

    mapping(string => PasswordEntry) public passwordEntries;
    string[] public serviceNames;

    event PasswordEntryCreated(string indexed serviceName, address indexed owner);
    event PasswordDecrypted(string indexed serviceName, uint32 decryptedPassword);

    constructor() ZamaEthereumConfig() {}

    function createPasswordEntry(
        string calldata serviceName,
        externalEuint32 encryptedPassword,
        bytes calldata inputProof
    ) external {
        require(bytes(passwordEntries[serviceName].serviceName).length == 0, "Service already exists");
        require(FHE.isInitialized(FHE.fromExternal(encryptedPassword, inputProof)), "Invalid encrypted input");

        passwordEntries[serviceName] = PasswordEntry({
            serviceName: serviceName,
            encryptedPassword: FHE.fromExternal(encryptedPassword, inputProof),
            lastUpdated: block.timestamp,
            owner: msg.sender,
            isVerified: false,
            decryptedPassword: 0
        });

        FHE.allowThis(passwordEntries[serviceName].encryptedPassword);
        FHE.makePubliclyDecryptable(passwordEntries[serviceName].encryptedPassword);

        serviceNames.push(serviceName);
        emit PasswordEntryCreated(serviceName, msg.sender);
    }

    function verifyDecryption(
        string calldata serviceName,
        bytes memory abiEncodedClearPassword,
        bytes memory decryptionProof
    ) external {
        require(bytes(passwordEntries[serviceName].serviceName).length > 0, "Service does not exist");
        require(!passwordEntries[serviceName].isVerified, "Password already verified");

        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(passwordEntries[serviceName].encryptedPassword);

        FHE.checkSignatures(cts, abiEncodedClearPassword, decryptionProof);

        uint32 decodedPassword = abi.decode(abiEncodedClearPassword, (uint32));
        passwordEntries[serviceName].decryptedPassword = decodedPassword;
        passwordEntries[serviceName].isVerified = true;

        emit PasswordDecrypted(serviceName, decodedPassword);
    }

    function getEncryptedPassword(string calldata serviceName) external view returns (euint32) {
        require(bytes(passwordEntries[serviceName].serviceName).length > 0, "Service does not exist");
        return passwordEntries[serviceName].encryptedPassword;
    }

    function getPasswordEntry(string calldata serviceName) external view returns (
        string memory serviceName_,
        uint256 lastUpdated,
        address owner,
        bool isVerified,
        uint32 decryptedPassword
    ) {
        require(bytes(passwordEntries[serviceName].serviceName).length > 0, "Service does not exist");
        PasswordEntry storage entry = passwordEntries[serviceName];

        return (
            entry.serviceName,
            entry.lastUpdated,
            entry.owner,
            entry.isVerified,
            entry.decryptedPassword
        );
    }

    function getAllServiceNames() external view returns (string[] memory) {
        return serviceNames;
    }

    function updatePassword(
        string calldata serviceName,
        externalEuint32 newEncryptedPassword,
        bytes calldata inputProof
    ) external {
        require(bytes(passwordEntries[serviceName].serviceName).length > 0, "Service does not exist");
        require(msg.sender == passwordEntries[serviceName].owner, "Only owner can update");

        passwordEntries[serviceName].encryptedPassword = FHE.fromExternal(newEncryptedPassword, inputProof);
        passwordEntries[serviceName].lastUpdated = block.timestamp;
        passwordEntries[serviceName].isVerified = false;

        FHE.allowThis(passwordEntries[serviceName].encryptedPassword);
        FHE.makePubliclyDecryptable(passwordEntries[serviceName].encryptedPassword);
    }

    function isAvailable() public pure returns (bool) {
        return true;
    }
}

