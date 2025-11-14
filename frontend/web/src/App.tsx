import { ConnectButton } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import React, { useEffect, useState } from "react";
import { getContractReadOnly, getContractWithSigner } from "./components/useContract";
import "./App.css";
import { useAccount } from 'wagmi';
import { useFhevm, useEncrypt, useDecrypt } from '../fhevm-sdk/src';
import { ethers } from 'ethers';

interface PasswordEntry {
  id: string;
  website: string;
  username: string;
  encryptedPassword: string;
  strength: number;
  timestamp: number;
  creator: string;
  category: string;
  isVerified: boolean;
  decryptedValue?: number;
  publicValue1: number;
  publicValue2: number;
}

interface PasswordHistory {
  action: string;
  entryId: string;
  timestamp: number;
  details: string;
}

const App: React.FC = () => {
  const { address, isConnected } = useAccount();
  const [loading, setLoading] = useState(true);
  const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creatingPassword, setCreatingPassword] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{ visible: boolean; status: "pending" | "success" | "error"; message: string; }>({ 
    visible: false, 
    status: "pending" as const, 
    message: "" 
  });
  const [newPasswordData, setNewPasswordData] = useState({ 
    website: "", 
    username: "", 
    password: "", 
    category: "Social" 
  });
  const [selectedPassword, setSelectedPassword] = useState<PasswordEntry | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [contractAddress, setContractAddress] = useState("");
  const [fhevmInitializing, setFhevmInitializing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(5);
  const [history, setHistory] = useState<PasswordHistory[]>([]);
  const [showFAQ, setShowFAQ] = useState(false);

  const { status, initialize, isInitialized } = useFhevm();
  const { encrypt, isEncrypting} = useEncrypt();
  const { verifyDecryption, isDecrypting: fheIsDecrypting } = useDecrypt();

  const categories = ["Social", "Finance", "Work", "Personal", "Shopping"];

  useEffect(() => {
    const initFhevmAfterConnection = async () => {
      if (!isConnected) return;
      if (isInitialized || fhevmInitializing) return;
      
      try {
        setFhevmInitializing(true);
        await initialize();
      } catch (error) {
        setTransactionStatus({ 
          visible: true, 
          status: "error", 
          message: "FHEVM initialization failed" 
        });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      } finally {
        setFhevmInitializing(false);
      }
    };

    initFhevmAfterConnection();
  }, [isConnected, isInitialized, initialize, fhevmInitializing]);

  useEffect(() => {
    const loadDataAndContract = async () => {
      if (!isConnected) {
        setLoading(false);
        return;
      }
      
      try {
        await loadData();
        const contract = await getContractReadOnly();
        if (contract) setContractAddress(await contract.getAddress());
      } catch (error) {
        console.error('Failed to load data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDataAndContract();
  }, [isConnected]);

  const addToHistory = (action: string, entryId: string, details: string) => {
    setHistory(prev => [{
      action,
      entryId,
      timestamp: Date.now(),
      details
    }, ...prev.slice(0, 9)]);
  };

  const loadData = async () => {
    if (!isConnected) return;
    
    setIsRefreshing(true);
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const businessIds = await contract.getAllBusinessIds();
      const passwordsList: PasswordEntry[] = [];
      
      for (const businessId of businessIds) {
        try {
          const businessData = await contract.getBusinessData(businessId);
          passwordsList.push({
            id: businessId,
            website: businessData.name,
            username: businessData.description,
            encryptedPassword: businessId,
            strength: Number(businessData.publicValue1) || 0,
            timestamp: Number(businessData.timestamp),
            creator: businessData.creator,
            category: "General",
            isVerified: businessData.isVerified,
            decryptedValue: Number(businessData.decryptedValue) || 0,
            publicValue1: Number(businessData.publicValue1) || 0,
            publicValue2: Number(businessData.publicValue2) || 0
          });
        } catch (e) {
          console.error('Error loading password data:', e);
        }
      }
      
      setPasswords(passwordsList);
      addToHistory("REFRESH", "all", "Refreshed password list");
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Failed to load data" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setIsRefreshing(false); 
    }
  };

  const checkAvailability = async () => {
    if (!isConnected) return;
    
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const available = await contract.isAvailable();
      if (available) {
        setTransactionStatus({ visible: true, status: "success", message: "FHE System Available" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
        addToHistory("CHECK", "system", "Checked FHE system availability");
      }
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Availability check failed" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    }
  };

  const createPassword = async () => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Please connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return; 
    }
    
    setCreatingPassword(true);
    setTransactionStatus({ visible: true, status: "pending", message: "Encrypting password with FHE..." });
    
    try {
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract with signer");
      
      const passwordValue = parseInt(newPasswordData.password) || 0;
      const businessId = `pass-${Date.now()}`;
      
      if (passwordValue <= 0) throw new Error("Password must be a positive integer");
      
      const encryptedResult = await encrypt(contractAddress, address, passwordValue);
      
      const strength = Math.min(10, Math.max(1, Math.floor(newPasswordData.password.length / 2)));
      
      const tx = await contract.createBusinessData(
        businessId,
        newPasswordData.website,
        encryptedResult.encryptedData,
        encryptedResult.proof,
        strength,
        0,
        newPasswordData.username
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Storing encrypted password..." });
      await tx.wait();
      
      setTransactionStatus({ visible: true, status: "success", message: "Password encrypted and stored!" });
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
      
      await loadData();
      setShowCreateModal(false);
      setNewPasswordData({ website: "", username: "", password: "", category: "Social" });
      addToHistory("CREATE", businessId, `Created password for ${newPasswordData.website}`);
    } catch (e: any) {
      const errorMessage = e.message?.includes("user rejected transaction") 
        ? "Transaction rejected" 
        : "Creation failed: " + (e.message || "Unknown error");
      setTransactionStatus({ visible: true, status: "error", message: errorMessage });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setCreatingPassword(false); 
    }
  };

  const decryptPassword = async (entryId: string): Promise<number | null> => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Please connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    }
    
    setIsDecrypting(true);
    try {
      const contractRead = await getContractReadOnly();
      if (!contractRead) return null;
      
      const businessData = await contractRead.getBusinessData(entryId);
      if (businessData.isVerified) {
        const storedValue = Number(businessData.decryptedValue) || 0;
        setTransactionStatus({ visible: true, status: "success", message: "Password already verified" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
        addToHistory("DECRYPT", entryId, "Decrypted verified password");
        return storedValue;
      }
      
      const contractWrite = await getContractWithSigner();
      if (!contractWrite) return null;
      
      const encryptedValueHandle = await contractRead.getEncryptedValue(entryId);
      
      const result = await verifyDecryption(
        [encryptedValueHandle],
        contractAddress,
        (abiEncodedClearValues: string, decryptionProof: string) => 
          contractWrite.verifyDecryption(entryId, abiEncodedClearValues, decryptionProof)
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Verifying decryption..." });
      
      const clearValue = result.decryptionResult.clearValues[encryptedValueHandle];
      
      await loadData();
      setTransactionStatus({ visible: true, status: "success", message: "Password decrypted successfully!" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      addToHistory("DECRYPT", entryId, "Decrypted and verified password");
      
      return Number(clearValue);
      
    } catch (e: any) { 
      if (e.message?.includes("Data already verified")) {
        setTransactionStatus({ visible: true, status: "success", message: "Password already verified" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
        await loadData();
        return null;
      }
      
      setTransactionStatus({ visible: true, status: "error", message: "Decryption failed" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    } finally { 
      setIsDecrypting(false); 
    }
  };

  const filteredPasswords = passwords.filter(password =>
    password.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
    password.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    password.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentPasswords = filteredPasswords.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(filteredPasswords.length / itemsPerPage);

  const paginate = (pageNumber: number) => setCurrentPage(pageNumber);

  if (!isConnected) {
    return (
      <div className="app-container">
        <header className="app-header">
          <div className="logo">
            <div className="lock-icon">🔒</div>
            <h1>PassKey FHE</h1>
          </div>
          <div className="header-actions">
            <div className="wallet-connect-wrapper">
              <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
            </div>
          </div>
        </header>
        
        <div className="connection-prompt">
          <div className="connection-content">
            <div className="connection-icon">🔐</div>
            <h2>Connect Wallet to Access Encrypted Passwords</h2>
            <p>Secure your passwords with Fully Homomorphic Encryption on-chain protection</p>
            <div className="connection-steps">
              <div className="step">
                <span>1</span>
                <p>Connect your wallet to initialize FHE system</p>
              </div>
              <div className="step">
                <span>2</span>
                <p>Store passwords as encrypted integers on-chain</p>
              </div>
              <div className="step">
                <span>3</span>
                <p>Decrypt securely using zero-knowledge proofs</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isInitialized || fhevmInitializing) {
    return (
      <div className="loading-screen">
        <div className="fhe-spinner"></div>
        <p>Initializing FHE Encryption System...</p>
        <p className="loading-note">Securing your passwords with military-grade encryption</p>
      </div>
    );
  }

  if (loading) return (
    <div className="loading-screen">
      <div className="fhe-spinner"></div>
      <p>Loading encrypted password vault...</p>
    </div>
  );

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="logo-section">
          <div className="logo">
            <div className="lock-icon">🔒</div>
            <h1>PassKey FHE</h1>
          </div>
          <p className="tagline">Fully Homomorphic Encrypted Password Manager</p>
        </div>
        
        <div className="header-actions">
          <button className="check-availability-btn" onClick={checkAvailability}>
            Check FHE Status
          </button>
          <button className="faq-btn" onClick={() => setShowFAQ(true)}>
            FAQ
          </button>
          <button className="create-btn" onClick={() => setShowCreateModal(true)}>
            + New Password
          </button>
          <div className="wallet-connect-wrapper">
            <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
          </div>
        </div>
      </header>
      
      <div className="main-content">
        <div className="controls-section">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search passwords..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
            <div className="search-icon">🔍</div>
          </div>
          
          <div className="stats-panel">
            <div className="stat-item">
              <span className="stat-label">Total Passwords</span>
              <span className="stat-value">{passwords.length}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Verified</span>
              <span className="stat-value">
                {passwords.filter(p => p.isVerified).length}
              </span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Avg Strength</span>
              <span className="stat-value">
                {passwords.length > 0 
                  ? (passwords.reduce((sum, p) => sum + p.strength, 0) / passwords.length).toFixed(1)
                  : "0.0"
                }
              </span>
            </div>
          </div>
        </div>

        <div className="content-grid">
          <div className="passwords-section">
            <div className="section-header">
              <h2>Encrypted Passwords</h2>
              <button onClick={loadData} className="refresh-btn" disabled={isRefreshing}>
                {isRefreshing ? "🔄" : "Refresh"}
              </button>
            </div>
            
            <div className="passwords-list">
              {currentPasswords.length === 0 ? (
                <div className="no-passwords">
                  <div className="empty-icon">🔐</div>
                  <p>No passwords found</p>
                  <button className="create-btn" onClick={() => setShowCreateModal(true)}>
                    Add Your First Password
                  </button>
                </div>
              ) : (
                currentPasswords.map((password, index) => (
                  <div 
                    className={`password-card ${password.isVerified ? 'verified' : ''}`}
                    key={index}
                    onClick={() => setSelectedPassword(password)}
                  >
                    <div className="card-header">
                      <div className="website-name">{password.website}</div>
                      <div className={`strength-indicator strength-${password.strength}`}>
                        {password.strength}/10
                      </div>
                    </div>
                    <div className="card-content">
                      <div className="username">{password.username}</div>
                      <div className="password-display">
                        {password.isVerified && password.decryptedValue ? 
                          `••••${password.decryptedValue}` : "🔒 Encrypted"}
                      </div>
                    </div>
                    <div className="card-footer">
                      <div className="timestamp">
                        {new Date(password.timestamp * 1000).toLocaleDateString()}
                      </div>
                      <div className={`status ${password.isVerified ? 'verified' : 'encrypted'}`}>
                        {password.isVerified ? '✅ Verified' : '🔓 Verify'}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
            
            {totalPages > 1 && (
              <div className="pagination">
                <button 
                  onClick={() => paginate(currentPage - 1)} 
                  disabled={currentPage === 1}
                  className="page-btn"
                >
                  Previous
                </button>
                <span className="page-info">
                  Page {currentPage} of {totalPages}
                </span>
                <button 
                  onClick={() => paginate(currentPage + 1)} 
                  disabled={currentPage === totalPages}
                  className="page-btn"
                >
                  Next
                </button>
              </div>
            )}
          </div>
          
          <div className="sidebar">
            <div className="history-panel">
              <h3>Recent Activity</h3>
              <div className="history-list">
                {history.length === 0 ? (
                  <p className="no-activity">No recent activity</p>
                ) : (
                  history.map((item, index) => (
                    <div key={index} className="history-item">
                      <div className="activity-action">{item.action}</div>
                      <div className="activity-details">{item.details}</div>
                      <div className="activity-time">
                        {new Date(item.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            
            <div className="fhe-info-panel">
              <h3>FHE Protection</h3>
              <div className="fhe-flow">
                <div className="flow-step">
                  <div className="step-number">1</div>
                  <div className="step-text">Encrypt locally with FHE</div>
                </div>
                <div className="flow-step">
                  <div className="step-number">2</div>
                  <div className="step-text">Store encrypted on-chain</div>
                </div>
                <div className="flow-step">
                  <div className="step-number">3</div>
                  <div className="step-text">Decrypt with zero-knowledge</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {showCreateModal && (
        <ModalCreatePassword 
          onSubmit={createPassword} 
          onClose={() => setShowCreateModal(false)} 
          creating={creatingPassword} 
          passwordData={newPasswordData} 
          setPasswordData={setNewPasswordData}
          isEncrypting={isEncrypting}
          categories={categories}
        />
      )}
      
      {selectedPassword && (
        <PasswordDetailModal 
          password={selectedPassword} 
          onClose={() => setSelectedPassword(null)} 
          isDecrypting={isDecrypting || fheIsDecrypting} 
          decryptPassword={() => decryptPassword(selectedPassword.id)}
        />
      )}
      
      {showFAQ && (
        <FAQModal onClose={() => setShowFAQ(false)} />
      )}
      
      {transactionStatus.visible && (
        <div className="transaction-modal">
          <div className="transaction-content">
            <div className={`transaction-icon ${transactionStatus.status}`}>
              {transactionStatus.status === "pending" && <div className="fhe-spinner"></div>}
              {transactionStatus.status === "success" && "✓"}
              {transactionStatus.status === "error" && "✗"}
            </div>
            <div className="transaction-message">{transactionStatus.message}</div>
          </div>
        </div>
      )}
    </div>
  );
};

const ModalCreatePassword: React.FC<{
  onSubmit: () => void; 
  onClose: () => void; 
  creating: boolean;
  passwordData: any;
  setPasswordData: (data: any) => void;
  isEncrypting: boolean;
  categories: string[];
}> = ({ onSubmit, onClose, creating, passwordData, setPasswordData, isEncrypting, categories }) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setPasswordData({ ...passwordData, [name]: value });
  };

  return (
    <div className="modal-overlay">
      <div className="create-password-modal">
        <div className="modal-header">
          <h2>Add New Password</h2>
          <button onClick={onClose} className="close-modal">×</button>
        </div>
        
        <div className="modal-body">
          <div className="fhe-notice">
            <strong>FHE 🔐 Encryption Notice</strong>
            <p>Password will be encrypted as an integer using Zama FHE technology</p>
          </div>
          
          <div className="form-group">
            <label>Website/Service *</label>
            <input 
              type="text" 
              name="website" 
              value={passwordData.website} 
              onChange={handleChange} 
              placeholder="Enter website name..." 
            />
          </div>
          
          <div className="form-group">
            <label>Username/Email *</label>
            <input 
              type="text" 
              name="username" 
              value={passwordData.username} 
              onChange={handleChange} 
              placeholder="Enter username..." 
            />
          </div>
          
          <div className="form-group">
            <label>Password (Integer only) *</label>
            <input 
              type="number" 
              name="password" 
              value={passwordData.password} 
              onChange={handleChange} 
              placeholder="Enter numeric password..." 
              min="1"
            />
            <div className="input-hint">FHE Encrypted Integer</div>
          </div>
          
          <div className="form-group">
            <label>Category</label>
            <select name="category" value={passwordData.category} onChange={handleChange}>
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="cancel-btn">Cancel</button>
          <button 
            onClick={onSubmit} 
            disabled={creating || isEncrypting || !passwordData.website || !passwordData.username || !passwordData.password} 
            className="submit-btn"
          >
            {creating || isEncrypting ? "Encrypting..." : "Encrypt & Store"}
          </button>
        </div>
      </div>
    </div>
  );
};

const PasswordDetailModal: React.FC<{
  password: PasswordEntry;
  onClose: () => void;
  isDecrypting: boolean;
  decryptPassword: () => Promise<number | null>;
}> = ({ password, onClose, isDecrypting, decryptPassword }) => {
  const [decryptedValue, setDecryptedValue] = useState<number | null>(null);

  const handleDecrypt = async () => {
    const value = await decryptPassword();
    setDecryptedValue(value);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="modal-overlay">
      <div className="password-detail-modal">
        <div className="modal-header">
          <h2>Password Details</h2>
          <button onClick={onClose} className="close-modal">×</button>
        </div>
        
        <div className="modal-body">
          <div className="password-info">
            <div className="info-row">
              <label>Website:</label>
              <span>{password.website}</span>
            </div>
            <div className="info-row">
              <label>Username:</label>
              <span>{password.username}</span>
            </div>
            <div className="info-row">
              <label>Strength:</label>
              <span className={`strength-badge strength-${password.strength}`}>
                {password.strength}/10
              </span>
            </div>
            <div className="info-row">
              <label>Created:</label>
              <span>{new Date(password.timestamp * 1000).toLocaleString()}</span>
            </div>
            <div className="info-row">
              <label>Creator:</label>
              <span>{password.creator.substring(0, 8)}...{password.creator.substring(36)}</span>
            </div>
          </div>
          
          <div className="password-section">
            <div className="section-header">
              <h3>Encrypted Password</h3>
              <button 
                className={`decrypt-btn ${(password.isVerified || decryptedValue !== null) ? 'decrypted' : ''}`}
                onClick={handleDecrypt} 
                disabled={isDecrypting}
              >
                {isDecrypting ? "Decrypting..." : 
                 password.isVerified ? "✅ Verified" : 
                 decryptedValue !== null ? "🔄 Re-verify" : "🔓 Decrypt"}
              </button>
            </div>
            
            <div className="password-display-area">
              <div className="password-value">
                {password.isVerified ? 
                  `••••${password.decryptedValue}` : 
                  decryptedValue !== null ? 
                  `••••${decryptedValue}` : 
                  "🔒 Encrypted (FHE Protected)"}
              </div>
              {(password.isVerified || decryptedValue !== null) && (
                <button 
                  className="copy-btn"
                  onClick={() => copyToClipboard(password.isVerified ? 
                    password.decryptedValue?.toString() || "" : 
                    decryptedValue?.toString() || "")}
                >
                  Copy
                </button>
              )}
            </div>
            
            <div className="encryption-info">
              <div className="encryption-status">
                Status: {password.isVerified ? 
                  <span className="verified">On-chain Verified</span> : 
                  decryptedValue !== null ? 
                  <span className="local-decrypted">Locally Decrypted</span> : 
                  <span className="encrypted">FHE Encrypted</span>}
              </div>
              <p className="encryption-desc">
                Password is stored as an encrypted integer on-chain using FHE technology
              </p>
            </div>
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="close-btn">Close</button>
        </div>
      </div>
    </div>
  );
};

const FAQModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const faqItems = [
    {
      question: "What is FHE?",
      answer: "Fully Homomorphic Encryption allows computation on encrypted data without decryption."
    },
    {
      question: "Why store passwords as integers?",
      answer: "Current FHE implementation supports integer operations. Passwords are stored as numeric values."
    },
    {
      question: "Is my data secure?",
      answer: "Yes, passwords are encrypted on-chain and can only be decrypted with your private key."
    },
    {
      question: "How does decryption work?",
      answer: "Decryption happens client-side with zero-knowledge proofs for on-chain verification."
    }
  ];

  return (
    <div className="modal-overlay">
      <div className="faq-modal">
        <div className="modal-header">
          <h2>Frequently Asked Questions</h2>
          <button onClick={onClose} className="close-modal">×</button>
        </div>
        
        <div className="modal-body">
          <div className="faq-list">
            {faqItems.map((item, index) => (
              <div key={index} className="faq-item">
                <h4>{item.question}</h4>
                <p>{item.answer}</p>
              </div>
            ))}
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="close-btn">Close</button>
        </div>
      </div>
    </div>
  );
};

export default App;

