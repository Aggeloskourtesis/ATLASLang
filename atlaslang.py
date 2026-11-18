from pathlib import Path
import pprint

from maltoolbox.language import LanguageGraph
from maltoolbox.model import Model
from maltoolbox.attackgraph import AttackGraph

from malsim import (
    MalSimulator,
    run_simulation,
    AttackerSettings,
)

from malsim.policies import DecisionAgent


# ============================================================
# CONFIGURATION
# ============================================================

LANG_FILE = Path("atlaslang.mal")


# ============================================================
# CASE STUDY DEFINITIONS
# ============================================================

CASE_STUDIES = {

    # ========================================================
    # AML.CS0062
    # RCE Vulnerability in Semantic Kernel Search Plugin
    # ========================================================

    "AML.CS0062": {

        "attacker_name": "AML_CS0062_Attacker",

        "entry_point":
            "MaliciousPrompt:llmPromptCrafting",

        "path": [
            "SemanticKernelAgent:aiEnabledProductOrService",
            "SemanticKernelAgent:directPromptInjection",
            "SearchPlugin:aiAgentToolInvocation",
            "InMemoryVectorStore:vulnerableFilterEvaluation",
            "HostOS:commandAndScriptingInterpreter",
            "HostOS:python",
            "HostOS:executeCode",
            "SemanticKernelHost:infectedComputer",
        ],

        "goal":
            "SemanticKernelHost:infectedComputer",
    },


    # ========================================================
    # AML.CS0000
    # Evasion of Deep Learning Detector for Malware C&C Traffic
    # ========================================================

    "AML.CS0000": {

        "attacker_name": "AML_CS0000_Attacker",

        "entry_point":
            "PublicPrePrintRepository:prePrintRepositories",

        "path": [
            "PublicC2Dataset:datasets",
            "ProxyC2Detector:createProxyAIModel",
            "AdversarialHTTPSample:manualModification",
            "ProductionC2Detector:verifyAttack",
            "ProductionC2Detector:evadeAIModel",
        ],

        "goal":
            "ProductionC2Detector:evadeAIModel",
    },


    # ========================================================
    # AML.CS0001
    # Botnet Domain Generation Algorithm (DGA)
    # Detection Evasion
    # ========================================================

    "AML.CS0001": {

        "attacker_name": "AML_CS0001_Attacker",

        "entry_point":
            "DGAResearchSources:searchOpenTechnicalDatabases",

        "path": [
            "PublicDGAAIArtifacts:acquirePublicAIArtifacts",
            "DGAMutationCapability:adversarialAIAttacks",
            "MutatedDGADomains:blackBoxOptimization",
            "ProductionDGADetector:verifyAttack",
            "ProductionDGADetector:evadeAIModel",
        ],

        "goal":
            "ProductionDGADetector:evadeAIModel",
    },
    # ========================================================
    # AML.CS0002
    # VirusTotal Poisoning
    # ========================================================

    "AML.CS0002": {

        "attacker_name":
            "AML_CS0002_Attacker",

        # AML.T0016.000
        "entry_point":
            "MetameTool:obtainAdversarialAIAttackImplementation",

        "path": [

            # AML.T0043
            "MetamorphicRansomwareVariants:"
            "craftAdversarialData",

            # AML.T0010.002
            "VirusTotalDataSupplyChain:"
            "aiSupplyChainCompromiseData",

            # AML.T0020
            "VirusTotalTrainingData:"
            "poisonTrainingData",
        ],

        "goal":
            "VirusTotalTrainingData:poisonTrainingData",
    },
    # ========================================================
    # AML.CS0003
    # Bypassing Cylance's AI Malware Detection
    # ========================================================

    "AML.CS0003": {

      "attacker_name":
          "AML_CS0003_Attacker",

     # S00 - AML.T0000
     "entry_point":
         "CylanceResearch:searchOpenTechnicalDatabases",

     "path": [

            # S01 - AML.T0047
            "CylanceMalwareDetector:"
            "aiEnabledProductOrService",

            # S02 - AML.T0063
            "CylanceMalwareDetector:"
            "discoverAIModelOutputs",

             # S03 - AML.T0017.000
            "CylanceBypassCapability:"
            "adversarialAIAttacks",

            # S04 - AML.T0043.003
            "CylanceBypassMalware:"
            "manualModification",

            # S05 - AML.T0015
            "CylanceMalwareDetector:"
            "evadeAIModel",
        ],

        "goal":
          "CylanceMalwareDetector:evadeAIModel",
    },
    # ========================================================
    # AML.CS0004
    # Camera Hijack Attack on Facial Recognition System
    # ========================================================

    "AML.CS0004": {

        "attacker_name":
            "AML_CS0004_Attacker",

        # AML.T0087
        "entry_point":
            "BlackMarketVictimIdentity:"
            "gatherVictimIdentityInformation",

        "path": [

            # AML.T0008.001
            "CustomizedAndroidPhone:"
            "consumerHardware",

            # AML.T0016.000
            "CameraHijackImplementation:"
            "obtainAdversarialAIAttackImplementation",

            # AML.T0016.001
            "VirtualCameraToolset:"
            "softwareTools",

            # AML.T0021
            "VictimImpersonationAccount:"
            "establishAccounts",

            # AML.T0047
            "TaxFacialRecognitionSystem:"
            "aiEnabledProductOrService",

            # AML.T0015
            "TaxFacialRecognitionSystem:"
            "evadeAIModel",

            # AML.T0048.000
            "TaxFraudImpact:"
            "financialHarm",
        ],

        "goal":
            "TaxFraudImpact:financialHarm",
    },

    # ========================================================
    # AML.CS0005
    # Attack on Machine Translation Services
    # (UC Berkeley: model replication + adversarial transfer)
    # ========================================================

    "AML.CS0005": {

        "attacker_name":
            "AML_CS0005_Attacker",

        # AML.T0000 - Search Open Technical Databases
        "entry_point":
            "TranslationResearchPapers:"
            "searchOpenTechnicalDatabases",

        "path": [

            # AML.T0002.000 - Acquire Public AI Artifacts: Datasets
            "PublicTranslationDatasets:"
            "datasets",

            # AML.T0002.001 - Acquire Public AI Artifacts: Models
            "PublicTranslationModels:"
            "models",

            # AML.T0040 - AI Model Inference API Access
            "ProductionTranslationService:"
            "aiModelInferenceAPIAccess",

            # AML.T0005.001 - Create Proxy AI Model: Train via Replication
            "ReplicatedTranslationModel:"
            "trainProxyViaReplication",

            # AML.T0048.004 - AI Intellectual Property Theft
            "TranslationModelIPTheft:"
            "aiIntellectualPropertyTheft",

            # AML.T0043.002 - Craft Adversarial Data: Black-Box Transfer
            "TransferredAdversarialSentences:"
            "blackBoxTransfer",

            # AML.T0015 - Evade AI Model
            "ProductionTranslationService:"
            "evadeAIModel",

            # AML.T0031 - Erode AI Model Integrity
            "ProductionTranslationService:"
            "erodeAIModelIntegrity",
        ],

        "goal":
            "ProductionTranslationService:"
            "erodeAIModelIntegrity",
    },
    
    # ========================================================
    # AML.CS0006
    # ClearviewAI Misconfiguration
    # ========================================================

    "AML.CS0006": {

        "attacker_name":
            "AML_CS0006_Attacker",

        # AML.T0021 - Establish Accounts
        "entry_point":
            "ClearviewRepositoryAccount:"
            "establishAccounts",

        "path": [

            # AML.T0036 - Data from Information Repositories
            "ClearviewRepositoryOS:"
            "dataFromInformationRepositories",

            # AML.T0002 - Acquire Public AI Artifacts
            "ClearviewPublicAIArtifacts:"
            "acquirePublicAIArtifacts",

            # AML.T0031 - Erode AI Model Integrity
            "ClearviewFacialRecognitionSystem:"
            "erodeAIModelIntegrity",
        ],

        "goal":
            "ClearviewFacialRecognitionSystem:"
            "erodeAIModelIntegrity",
    },
    
    # ========================================================
    # AML.CS0007
    # GPT-2 Model Replication
    # ========================================================

    "AML.CS0007": {

        "attacker_name":
            "AML_CS0007_Attacker",

        # AML.T0000
        "entry_point":
            "GPT2Research:"
            "searchOpenTechnicalDatabases",

        "path": [

            # AML.T0002.000
            "GPT2TrainingDataset:"
            "datasets",

            # AML.T0002.001
            "PublicGroverModel:"
            "models",

            # AML.T0008.000
            "GPT2ReplicationWorkspace:"
            "aiDevelopmentWorkspaces",

            # AML.T0005.000
            "ReplicatedGPT2Model:"
            "trainProxyViaGatheredAIArtifacts",
        ],

        "goal":
            "ReplicatedGPT2Model:"
            "trainProxyViaGatheredAIArtifacts",
    },
    
    # ========================================================
    # AML.CS0008
    # ProofPoint Evasion
    # ========================================================

    "AML.CS0008": {

        "attacker_name":
            "AML_CS0008_Attacker",

        # AML.T0047
        "entry_point":
            "ProofPointEmailProtection:"
            "aiEnabledProductOrService",

        "path": [

            # AML.T0063
            "ProofPointEmailProtection:"
            "discoverAIModelOutputs",

            # AML.T0005.001
            "ProofPointShadowModel:"
            "trainProxyViaReplication",

            # AML.T0043.002
            "ProofPointAdversarialEmail:"
            "blackBoxTransfer",

            # AML.T0015
            "ProofPointEmailProtection:"
            "evadeAIModel",
        ],

        "goal":
            "ProofPointEmailProtection:"
            "evadeAIModel",
    },
        
    # ========================================================
    # AML.CS0009
    # Tay Poisoning
    # ========================================================

    "AML.CS0009": {

        "attacker_name":
            "AML_CS0009_Attacker",

        # AML.T0047
        "entry_point":
            "TayChatbot:"
            "aiEnabledProductOrService",

        "path": [

            # AML.T0010.002
            "TayConversationSupplyChain:"
            "aiSupplyChainCompromiseData",

            # AML.T0020
            "TayOnlineTrainingData:"
            "poisonTrainingData",

            # AML.T0031
            "TayChatbot:"
            "erodeAIModelIntegrity",
        ],

        "goal":
            "TayChatbot:"
            "erodeAIModelIntegrity",
    },
    
    # ========================================================
    # AML.CS0010
    # Microsoft Azure Service Disruption
    # ========================================================

    "AML.CS0010": {

        "attacker_name":
            "AML_CS0010_Attacker",

        # AML.T0000
        "entry_point":
            "AzureResearch:"
            "searchOpenTechnicalDatabases",

        "path": [

            # AML.T0012 / ATT&CK T1078
            "AzureServiceOS:"
            "validAccounts",

            # AML.T0035
            "AzureArtifactCollection:"
            "aiArtifactCollection",

            # AML.T0025
            "AzureArtifactExfiltration:"
            "exfiltrationViaCyberMeans",

            # AML.T0043.000
            "AzureAdversarialExample:"
            "whiteBoxOptimization",

            # AML.T0040
            "AzureTargetService:"
            "aiModelInferenceAPIAccess",

            # AML.T0042
            "AzureTargetService:"
            "verifyAttack",

            # AML.T0015
            "AzureTargetService:"
            "evadeAIModel",
        ],

        "goal":
            "AzureTargetService:"
            "evadeAIModel",
    },
    
    # ========================================================
    # AML.CS0011
    # Microsoft Edge AI Evasion
    # ========================================================

    "AML.CS0011": {

        "attacker_name":
            "AML_CS0011_Attacker",

        # AML.T0000
        "entry_point":
            "EdgeAIResearch:"
            "searchOpenTechnicalDatabases",

        "path": [

            # AML.T0002
            "EdgePublicBaseModel:"
            "acquirePublicAIArtifacts",

            # AML.T0040
            "EdgePublicInferenceService:"
            "aiModelInferenceAPIAccess",

            # AML.T0043.001
            "EdgeAdversarialImage:"
            "blackBoxOptimization",

            # AML.T0015
            "MicrosoftEdgeTargetModel:"
            "evadeAIModel",
        ],

        "goal":
            "MicrosoftEdgeTargetModel:"
            "evadeAIModel",
    },
    
    # ========================================================
    # AML.CS0012
    # Face Identification System Evasion
    # via Physical Countermeasures
    # ========================================================

    "AML.CS0012": {

        "attacker_name":
            "AML_CS0012_Attacker",

        # AML.T0000
        "entry_point":
            "FaceIDResearch:"
            "searchOpenTechnicalDatabases",

        "path": [

            # AML.T0012 / ATT&CK T1078
            "FaceIDServiceOS:"
            "validAccounts",

            # AML.T0040
            "CommercialFaceIDService:"
            "aiModelInferenceAPIAccess",

            # AML.T0013
            "CommercialFaceIDService:"
            "discoverAIModelOntology",

            # AML.T0002.000
            "PublicFaceDataset:"
            "datasets",

            # AML.T0005
            "FaceIDProxyModel:"
            "createProxyAIModel",

            # AML.T0043.000
            "OptimizedFacePattern:"
            "whiteBoxOptimization",

            # AML.T0008.003
            "PrintedAdversarialSticker:"
            "physicalCountermeasures",

            # AML.T0041
            "FaceCaptureEnvironment:"
            "physicalEnvironmentAccess",

            # AML.T0015
            "CommercialFaceIDService:"
            "evadeAIModel",
        ],

        "goal":
            "CommercialFaceIDService:"
            "evadeAIModel",
    },
        
    # ========================================================
    # AML.CS0013
    # Backdoor Attack on Deep Learning Models in Mobile Apps
    # ========================================================

    "AML.CS0013": {

        "attacker_name":
            "AML_CS0013_Attacker",

        # AML.T0004
        "entry_point":
            "MobileAppRepositoryResearch:"
            "searchApplicationRepositories",

        "path": [

            # AML.T0002.001
            "DownloadedMobileModel:"
            "models",

            # AML.T0044
            "TargetMobileAIModel:"
            "fullAIModelAccess",

            # AML.T0017.000
            "NeuralPayloadCapability:"
            "adversarialAIAttacks",

            # AML.T0018.001
            "TargetMobileAIModel:"
            "modifyAIModelArchitecture",

            # AML.T0042
            "TargetMobileAIModel:"
            "verifyAttack",

            # AML.T0010.003
            "CompromisedMobileModelSupplyChain:"
            "aiSupplyChainCompromiseModel",

            # AML.T0043.004
            "VisualBackdoorTrigger:"
            "insertBackdoorTrigger",

            # AML.T0041
            "VictimPhysicalEnvironment:"
            "physicalEnvironmentAccess",

            # AML.T0015
            "TargetMobileAIModel:"
            "evadeAIModel",
        ],

        "goal":
            "TargetMobileAIModel:"
            "evadeAIModel",
    },
    
    # ========================================================
    # AML.CS0014
    # Confusing Antimalware Neural Networks
    # ========================================================

    "AML.CS0014": {

        "attacker_name":
            "AML_CS0014_Attacker",

        # AML.T0001
        "entry_point":
            "KasperskyGrayBoxResearch:"
            "searchOpenAIVulnerabilityAnalysis",

        "path": [

            # AML.T0003
            "KasperskyGrayBoxResearch:"
            "searchVictimOwnedWebsites",

            # AML.T0047
            "KasperskyAntimalwareModel:"
            "aiEnabledProductOrService",

            # AML.T0002.000
            "KasperskyLabeledDataset:"
            "datasets",

            # AML.T0005
            "KasperskyProxyModel:"
            "createProxyAIModel",

            # AML.T0017.000
            "KasperskyAdversarialCapability:"
            "adversarialAIAttacks",

            # AML.T0043.002
            "KasperskyAdversarialMalware:"
            "blackBoxTransfer",

            # AML.T0042
            "KasperskyAntimalwareModel:"
            "verifyAttack",

            # AML.T0015
            "KasperskyAntimalwareModel:"
            "evadeAIModel",
        ],

        "goal":
            "KasperskyAntimalwareModel:"
            "evadeAIModel",
    },
        
    # ========================================================
    # AML.CS0015
    # Compromised PyTorch Dependency Chain
    # ========================================================

    "AML.CS0015": {

        "attacker_name":
            "AML_CS0015_Attacker",

        # AML.T0010.001
        "entry_point":
            "CompromisedTorchtritonPackage:"
            "aiSupplyChainCompromiseSoftware",

        "path": [

            # AML.T0037 / ATT&CK T1005
            "PyTorchVictimHost:"
            "dataFromLocalSystem",

            # AML.T0025
            "PyTorchDNSExfiltration:"
            "exfiltrationViaCyberMeans",
        ],

        "goal":
            "PyTorchDNSExfiltration:"
            "exfiltrationViaCyberMeans",
    },
        
    # ========================================================
    # AML.CS0016
    # MathGPT Prompt Injection - Credential Exposure
    # ========================================================

    "AML.CS0016": {

        "attacker_name":
            "AML_CS0016_Attacker",

        # AML.T0001
        "entry_point":
            "MathGPTResearch:"
            "searchOpenAIVulnerabilityAnalysis",

        "path": [

            # AML.T0047
            "MathGPTApplication:"
            "aiEnabledProductOrService",

            # AML.T0051.000
            "MathGPTApplication:"
            "directPromptInjection",

            # AML.T0042
            "MathGPTApplication:"
            "verifyAttack",

            # AML.T0093
            "MathGPTApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            # AML.T0053
            "MathGPTPythonInterpreter:"
            "aiAgentToolInvocation",

            # AML.T0055 / ATT&CK T1552
            "MathGPTHost:"
            "unsecuredCredentials",

            # AML.T0048.000
            "MathGPTFinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "MathGPTFinancialImpact:"
            "financialHarm",
    },
        
    # ========================================================
    # AML.CS0016 - DoS branch
    # ========================================================

    "AML.CS0016-DOS": {

        "attacker_name":
            "AML_CS0016_DOS_Attacker",

        "entry_point":
            "MathGPTResearch:"
            "searchOpenAIVulnerabilityAnalysis",

        "path": [

            "MathGPTApplication:"
            "aiEnabledProductOrService",

            "MathGPTApplication:"
            "directPromptInjection",

            "MathGPTApplication:"
            "verifyAttack",

            "MathGPTApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            "MathGPTPythonInterpreter:"
            "aiAgentToolInvocation",

            # AML.T0029
            "MathGPTServiceImpact:"
            "denialOfAIService",
        ],

        "goal":
            "MathGPTServiceImpact:"
            "denialOfAIService",
    },
    
    # ========================================================
    # AML.CS0017
    # Bypassing ID.me Identity Verification
    # ========================================================

    "AML.CS0017": {

        "attacker_name":
            "AML_CS0017_Attacker",

        # AML.T0047
        "entry_point":
            "IDMeIdentityVerificationSystem:"
            "aiEnabledProductOrService",

        "path": [

            # AML.T0015
            "IDMeIdentityVerificationSystem:"
            "evadeAIModel",

            # AML.T0048.000
            "IDMeFraudImpact:"
            "financialHarm",
        ],

        "goal":
            "IDMeFraudImpact:"
            "financialHarm",
    },
    
    # ========================================================
    # AML.CS0018
    # Arbitrary Code Execution with Google Colab
    # ========================================================

    "AML.CS0018": {

        "attacker_name":
            "AML_CS0018_Attacker",

        # AML.T0017
        "entry_point":
            "ColabMaliciousNotebookCapability:"
            "developCapabilities",

        "path": [

            # AML.T0010.001
            "CompromisedColabNotebook:"
            "aiSupplyChainCompromiseSoftware",

            # AML.T0012
            "ColabDriveAccess:"
            "validAccounts",

            # AML.T0011
            "ColabNotebookExecution:"
            "userExecution",

            # AML.T0035
            "ColabArtifactCollection:"
            "aiArtifactCollection",

            # AML.T0025
            "ColabExfiltration:"
            "exfiltrationViaCyberMeans",

            # AML.T0048.004
            "ColabExternalImpact:"
            "aiIntellectualPropertyTheft",

            # AML.T0048
            "ColabExternalImpact:"
            "externalHarms",
        ],

        "goal":
            "ColabExternalImpact:"
            "externalHarms",
    },
    
    # ========================================================
    # AML.CS0019
    # PoisonGPT
    # ========================================================

    "AML.CS0019": {

        "attacker_name":
            "AML_CS0019_Attacker",

        # AML.T0002.001
        "entry_point":
            "PublicGPTJModel:"
            "models",

        "path": [

            # AML.T0018.000
            "PoisonedGPTJModel:"
            "poisonAIModel",

            # AML.T0042
            "PoisonedGPTJModel:"
            "verifyAttack",

            # AML.T0115.001
            "HuggingFacePoisonedModelPublisher:"
            "publishPoisonedModels",

            # AML.T0010.003
            "PoisonGPTModelSupplyChain:"
            "aiSupplyChainCompromiseModel",

            # AML.T0031
            "VictimPoisonGPTModel:"
            "erodeAIModelIntegrity",

            # AML.T0048.001
            "PoisonGPTReputationImpact:"
            "reputationalHarm",
        ],

        "goal":
            "PoisonGPTReputationImpact:"
            "reputationalHarm",
    },
    
    # ========================================================
    # AML.CS0020
    # Indirect Prompt Injection Threats:
    # Bing Chat Data Pirate
    # ========================================================

    "AML.CS0020": {

        "attacker_name":
            "AML_CS0020_Attacker",

        # AML.T0017
        "entry_point":
            "BingDataPirateCapability:"
            "developCapabilities",

        "path": [

            # AML.T0068
            "BingHiddenPrompt:"
            "llmPromptObfuscation",

            # AML.T0051.001
            "BingChatConversation:"
            "indirectPromptInjection",

            # AML.T0052.000
            "BingSocialEngineering:"
            "spearphishingViaSocialEngineeringLLM",

            # AML.T0048.003
            "BingUserImpact:"
            "userHarm",
        ],

        "goal":
            "BingUserImpact:"
            "userHarm",
    },
        
    # ========================================================
    # AML.CS0021
    # ChatGPT Conversation Exfiltration
    # ========================================================

    "AML.CS0021": {

        "attacker_name":
            "AML_CS0021_Attacker",

        # AML.T0065
        "entry_point":
            "ChatGPTExfiltrationPrompt:"
            "llmPromptCrafting",

        "path": [

            # AML.T0079
            "ChatGPTStagedPrompt:"
            "stageCapabilities",

            # AML.T0078 / ATT&CK T1189
            "ChatGPTDriveByBrowser:"
            "driveByCompromise",

            # AML.T0051.001
            "ChatGPTExfiltrationConversation:"
            "indirectPromptInjection",

            # AML.T0053
            "ChatGPTBrowsingPlugin:"
            "aiAgentToolInvocation",

            # AML.T0077
            "ChatGPTRenderedExfiltration:"
            "llmResponseRendering",

            # AML.T0048.003
            "ChatGPTUserImpact:"
            "userHarm",
        ],

        "goal":
            "ChatGPTUserImpact:"
            "userHarm",
    },
        
    # ========================================================
    # AML.CS0022
    # ChatGPT Package Hallucination
    # ========================================================

    "AML.CS0022": {

        "attacker_name":
            "AML_CS0022_Attacker",

        # AML.T0040
        "entry_point":
            "ChatGPTPackageService:"
            "aiModelInferenceAPIAccess",

        "path": [

            # AML.T0062
            "ChatGPTPackageService:"
            "discoverLLMHallucinations",

            # AML.T0060
            "HallucinatedPackagePublisher:"
            "publishHallucinatedEntities",

            # AML.T0010.001
            "HallucinatedPackageSupplyChain:"
            "aiSupplyChainCompromiseSoftware",

            # AML.T0011.001
            "HallucinatedPackageExecution:"
            "maliciousPackage",

            # AML.T0048.003
            "HallucinatedPackageUserImpact:"
            "userHarm",
        ],

        "goal":
            "HallucinatedPackageUserImpact:"
            "userHarm",
    },
        
    # ========================================================
    # AML.CS0023
    # ShadowRay: Hijacking Exposed Ray Clusters
    # ========================================================

    "AML.CS0023": {

        "attacker_name":
            "AML_CS0023_Attacker",

        # AML.T0006
        "entry_point":
            "ShadowRayResearch:"
            "activeScanning",

        "path": [

            # AML.T0049
            "ExposedRayCluster:"
            "exploitPublicFacingApplication",

            # AML.T0035
            "ShadowRayArtifactCollection:"
            "aiArtifactCollection",

            # AML.T0055 / ATT&CK T1552
            "ExposedRayCluster:"
            "unsecuredCredentials",

            # AML.T0025
            "ShadowRayExfiltration:"
            "exfiltrationViaCyberMeans",

            # AML.T0010.003
            "ShadowRayModelSupplyChain:"
            "aiSupplyChainCompromiseModel",

            # AML.T0048.000
            "ShadowRayFinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "ShadowRayFinancialImpact:"
            "financialHarm",
    },
    
    # ========================================================
    # AML.CS0024
    # Morris II Worm - Data Leakage Branch
    # ========================================================

    "AML.CS0024": {

        "attacker_name":
            "AML_CS0024_Attacker",

        # S00 - AML.T0040
        "entry_point":
            "MorrisGenAIService:"
            "aiModelInferenceAPIAccess",

        "path": [

            # S01 - AML.T0065
            "MorrisAdversarialPrompt:"
            "llmPromptCrafting",

            # S02 - AML.T0042
            "MorrisGenAIService:"
            "verifyAttack",

            # S03 - AML.T0093
            "MorrisEmailApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            # S04 - AML.T0070
            "MorrisRAGDatabase:"
            "ragPoisoning",

            # S05 - AML.T0051.002
            "MorrisTriggeredConversation:"
            "triggeredPromptInjection",

            # S06 - AML.T0054
            "MorrisTriggeredConversation:"
            "llmJailbreak",

            # S08 - AML.T0085.000
            "MorrisRAGDatabase:"
            "ragDatabases",

            # S09 - AML.T0025
            "MorrisExfiltration:"
            "exfiltrationViaCyberMeans",

            # S11 - AML.T0048.003
            "MorrisUserImpact:"
            "userHarm",
        ],

        "goal":
            "MorrisUserImpact:"
            "userHarm",
    },
    
    # ========================================================
    # AML.CS0024 - Prompt Propagation Branch
    # ========================================================

    "AML.CS0024-PROPAGATION": {

        "attacker_name":
            "AML_CS0024_Propagation_Attacker",

        "entry_point":
            "MorrisGenAIService:"
            "aiModelInferenceAPIAccess",

        "path": [

            "MorrisAdversarialPrompt:"
            "llmPromptCrafting",

            "MorrisGenAIService:"
            "verifyAttack",

            "MorrisEmailApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            "MorrisRAGDatabase:"
            "ragPoisoning",

            "MorrisTriggeredConversation:"
            "triggeredPromptInjection",

            "MorrisTriggeredConversation:"
            "llmJailbreak",

            # S07 - AML.T0061
            "MorrisAdversarialPrompt:"
            "llmPromptSelfReplication",

            # S10 - AML.T0143
            "MorrisPromptPropagation:"
            "llmPromptPropagation",
        ],

        "goal":
            "MorrisPromptPropagation:"
            "llmPromptPropagation",
    },
    
    # ========================================================
    # AML.CS0025
    # Web-Scale Data Poisoning: Split-View Attack
    # ========================================================

    "AML.CS0025": {

        "attacker_name":
            "AML_CS0025_Attacker",

        # S00 - AML.T0002.000
        "entry_point":
            "WebScaleDataset:"
            "datasets",

        "path": [

            # S01 - AML.T0008.002
            "ExpiredDatasetDomains:"
            "domains",

            # S02 - AML.T0020
            "PoisonedWebScaleData:"
            "poisonTrainingData",

            # S03 - AML.T0115.000
            "SplitViewDatasetPublisher:"
            "publishPoisonedDatasets",

            # S04 - AML.T0059
            "PoisonedWebScaleData:"
            "erodeDatasetIntegrity",

            # S05 - AML.T0031
            "SplitViewAffectedModel:"
            "erodeAIModelIntegrity",
        ],

        "goal":
            "SplitViewAffectedModel:"
            "erodeAIModelIntegrity",
    },
        
    # ========================================================
    # AML.CS0026
    # Financial Transaction Hijacking with M365 Copilot
    # ========================================================

    "AML.CS0026": {

        "attacker_name":
            "AML_CS0026_Attacker",

        # S00 - AML.T0064
        "entry_point":
            "M365CopilotResearch:"
            "gatherRAGIndexedTargets",

        "path": [

            # S01 - AML.T0047
            "M365Copilot:"
            "aiEnabledProductOrService",

            # S02 - AML.T0069.000
            "M365Copilot:"
            "specialCharacterSets",

            # S03 - AML.T0069.001
            "M365Copilot:"
            "systemInstructionKeywords",

            # S04 - AML.T0066
            "M365MaliciousEmail:"
            "retrievalContentCrafting",

            # S05 - AML.T0065
            "M365MaliciousEmail:"
            "llmPromptCrafting",

            # S06 - AML.T0093
            "M365Copilot:"
            "promptInfiltrationViaPublicFacingApplication",

            # S07 - AML.T0068
            "M365MaliciousEmail:"
            "llmPromptObfuscation",

            # S08 - AML.T0070
            "M365CopilotRAG:"
            "ragPoisoning",

            # S09 - AML.T0071
            "M365CopilotRAG:"
            "falseRAGEntryInjection",

            # S10 - AML.T0051.001
            "M365CopilotConversation:"
            "indirectPromptInjection",

            # S11 - AML.T0053
            "M365SearchEnterpriseTool:"
            "aiAgentToolInvocation",

            # S12 - AML.T0067.000
            "M365ManipulatedResponse:"
            "citations",

            # S13 - AML.T0048.000
            "M365FinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "M365FinancialImpact:"
            "financialHarm",
    },
    
    # ========================================================
    # AML.CS0027
    # Organization Confusion on Hugging Face
    # ========================================================

    "AML.CS0027": {

        "attacker_name":
            "AML_CS0027_Attacker",

        # S00 - AML.T0021
        "entry_point":
            "FakeHuggingFaceOrganization:"
            "establishAccounts",

        "path": [

            # S01 - AML.T0073
            "FakeHuggingFaceOrganization:"
            "impersonation",

            # S02 - AML.T0044
            "HuggingFacePrivateModel:"
            "fullAIModelAccess",

            # S03 - AML.T0048.004
            "HuggingFaceModelIPTheft:"
            "aiIntellectualPropertyTheft",

            # S04 - AML.T0018.002
            "HuggingFacePrivateModel:"
            "embedMalware",

            # S05 - AML.T0115.001
            "HFOrgConfusionPublisher:"
            "publishPoisonedModels",

            # S06 - AML.T0010.003
            "HuggingFaceModelSupplyChain:"
            "aiSupplyChainCompromiseModel",

            # S07 - AML.T0011.000
            "HuggingFacePrivateModel:"
            "unsafeAIArtifacts",

            # S08 - AML.T0074
            "VictimAIEnvironment:"
            "masquerading",

            # S09 - AML.T0072
            "SliverC2Channel:"
            "cyberCommunicationChannel",

            # S10 - AML.T0055
            "VictimAIEnvironment:"
            "unsecuredCredentials",

            # S11 - AML.T0025
            "SliverCredentialExfiltration:"
            "exfiltrationViaCyberMeans",

            # S12 - AML.T0007
            "VictimAIArtifactDiscovery:"
            "discoverAIArtifacts",

            # S13 - AML.T0016.000
            "EasyEditTool:"
            "obtainAdversarialAIAttackImplementation",

            # S14 - AML.T0018.000
            "VictimLlamaModel:"
            "poisonAIModel",

            # S15 - AML.T0048
            "ManipulatedModelExternalHarm:"
            "externalHarms",
        ],

        "goal":
            "ManipulatedModelExternalHarm:"
            "externalHarms",
    },
    
    # ========================================================
    # AML.CS0028
    # AI Model Tampering via Supply Chain Attack
    # ========================================================

    "AML.CS0028": {

        "attacker_name":
            "AML_CS0028_Attacker",

        # S00 - AML.T0004
        "entry_point":
            "ContainerRegistryResearch:"
            "searchApplicationRepositories",

        "path": [

            # S01 - AML.T0049
            "ExposedAIContainerRegistry:"
            "exploitPublicFacingApplication",

            # S02 - AML.T0007
            "ContainerRegistryArtifactDiscovery:"
            "discoverAIArtifacts",

            # S03 - AML.T0044
            "ExposedRegistryAIModel:"
            "fullAIModelAccess",

            # S04 - AML.T0048.004
            "ContainerRegistryModelIPTheft:"
            "aiIntellectualPropertyTheft",

            # S05 - AML.T0018.000
            "ExposedRegistryAIModel:"
            "poisonAIModel",

            # S06 - AML.T0018.001
            "ExposedRegistryAIModel:"
            "modifyAIModelArchitecture",

            # S07 - AML.T0010.004
            "ExposedAIContainerRegistry:"
            "containerRegistry",

            # S08 - AML.T0015
            "DeployedTamperedAIModel:"
            "evadeAIModel",
        ],

        "goal":
            "DeployedTamperedAIModel:"
            "evadeAIModel",
    },
    
    # ========================================================
    # AML.CS0029
    # Google Bard Conversation Exfiltration
    # ========================================================

    "AML.CS0029": {

        "attacker_name":
            "AML_CS0029_Attacker",

        # S00 - AML.T0065
        "entry_point":
            "BardExfiltrationPrompt:"
            "llmPromptCrafting",

        "path": [

            # S01 - AML.T0008
            "BardGoogleAppsInfrastructure:"
            "acquireInfrastructure",

            # S02 - AML.T0017
            "BardExfiltrationCapability:"
            "developCapabilities",

            # S03 - AML.T0093
            "BardTargetApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            # S04 - AML.T0051.001
            "BardConversation:"
            "indirectPromptInjection",

            # S05 - AML.T0077
            "BardRenderedExfiltration:"
            "llmResponseRendering",

            # S06 - AML.T0048.003
            "BardUserImpact:"
            "userHarm",
        ],

        "goal":
            "BardUserImpact:"
            "userHarm",
    },
    
    # ========================================================
    # AML.CS0030
    # LLMjacking:
    # Stolen Cloud Credentials Used to Access Cloud LLM Services
    # ========================================================

    "AML.CS0030": {

        "attacker_name":
            "AML_CS0030_Attacker",

        # S00 - AML.T0049
        "entry_point":
            "LLMJackingVictimHost:"
            "exploitPublicFacingApplication",

        "path": [

            # S01 - AML.T0055
            "LLMJackingVictimHost:"
            "unsecuredCredentials",

            # S02 - AML.T0012
            "CompromisedCloudLLMEnvironment:"
            "validAccounts",

            # S03 - AML.T0016.001
            # keychecker
            "LLMJackingKeychecker:"
            "softwareTools",

            # S04 - AML.T0075
            "LLMJackingResourceDiscovery:"
            "enterpriseResourceDiscovery",

            # S05 - AML.T0016.001
            # OAI Reverse Proxy
            "LLMJackingReverseProxy:"
            "softwareTools",

            # S06 - AML.T0048.000
            "LLMJackingFinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "LLMJackingFinancialImpact:"
            "financialHarm",
    },
        
    # ========================================================
    # AML.CS0031
    # Malicious Models on Hugging Face
    # ========================================================

    "AML.CS0031": {

        "attacker_name":
            "AML_CS0031_Attacker",

        # S00 - AML.T0018.002
        "entry_point":
            "CS0031MaliciousHuggingFaceModel:"
            "embedMalware",

        "path": [

            # S01 - AML.T0115.001
            "CS0031HuggingFacePublisher:"
            "publishPoisonedModels",

            # S02 - AML.T0076
            "CS0031MaliciousHuggingFaceModel:"
            "corruptAIModel",

            # S03 - AML.T0010
            "CS0031ModelSupplyChain:"
            "aiSupplyChainCompromise",

            # S04 - AML.T0011.000
            "CS0031MaliciousHuggingFaceModel:"
            "unsafeAIArtifacts",

            # S05 - AML.T0072
            "CS0031ReverseShell:"
            "cyberCommunicationChannel",
        ],

        "goal":
            "CS0031ReverseShell:"
            "cyberCommunicationChannel",
    },
    
    # ========================================================
    # AML.CS0032
    # Attempted Evasion of ML Phishing Webpage Detection System
    # ========================================================

    "AML.CS0032": {

        "attacker_name":
            "AML_CS0032_Attacker",

        # S00 - AML.T0043.003
        "entry_point":
            "ModifiedPhishingWebpage:"
            "manualModification",

        "path": [

            # S01 - AML.T0015
            "PhishingVisualSimilarityModel:"
            "evadeAIModel",

            # S02 - AML.T0052 / ATT&CK T1566
            "CS0032PhishingCampaign:"
            "phishing",

            # S03 - AML.T0048.003
            "CS0032UserImpact:"
            "userHarm",
        ],

        "goal":
            "CS0032UserImpact:"
            "userHarm",
    },
        
    # ========================================================
    # AML.CS0033
    # Live Deepfake Image Injection to Evade Mobile KYC
    # Verification
    # ========================================================

    "AML.CS0033": {

        "attacker_name":
            "AML_CS0033_Attacker",

        # S00 - AML.T0087
        "entry_point":
            "CS0033VictimIdentity:"
            "gatherVictimIdentityInformation",

        "path": [

            # S01 - AML.T0016.002
            "CS0033Faceswap:"
            "generativeAI",

            # S02 - AML.T0016.001
            "CS0033OBS:"
            "softwareTools",

            # S03 - AML.T0016
            "CS0033VirtualCamera:"
            "obtainCapabilities",

            # S04 - AML.T0088
            "CS0033LiveDeepfake:"
            "generateDeepfakes",

            # S05 - AML.T0021
            "CS0033FraudulentAccount:"
            "establishAccounts",

            # S06 - AML.T0047
            "CS0033MobileKYCSystem:"
            "aiEnabledProductOrService",

            # S07 - AML.T0015
            "CS0033MobileKYCSystem:"
            "evadeAIModel",

            # S08 - AML.T0073
            "CS0033FraudulentAccount:"
            "impersonation",

            # S09 - AML.T0048.000
            "CS0033FinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "CS0033FinancialImpact:"
            "financialHarm",
    },
        
    # ========================================================
    # AML.CS0034
    # ProKYC: Deepfake Tool for Account Fraud Attacks
    # ========================================================

    "AML.CS0034": {

        "attacker_name":
            "AML_CS0034_Attacker",

        # S00 - AML.T0087
        "entry_point":
            "CS0034VictimIdentity:"
            "gatherVictimIdentityInformation",

        "path": [

            # S01 - AML.T0016.002
            "CS0034ProKYCTool:"
            "generativeAI",

            # S02 - AML.T0088
            # Fake identity document
            "CS0034FakeIdentityDocument:"
            "generateDeepfakes",

            # S03 - AML.T0088
            # Matching deepfake selfie video
            "CS0034DeepfakeSelfieVideo:"
            "generateDeepfakes",

            # S04 - AML.T0021
            "CS0034FraudulentAccount:"
            "establishAccounts",

            # S05 - AML.T0047
            "CS0034KYCSystem:"
            "aiEnabledProductOrService",

            # S06 - AML.T0015
            "CS0034KYCSystem:"
            "evadeAIModel",

            # S07 - AML.T0073
            "CS0034FraudulentAccount:"
            "impersonation",

            # S08 - AML.T0048.000
            "CS0034FinancialImpact:"
            "financialHarm",
        ],

        "goal":
            "CS0034FinancialImpact:"
            "financialHarm",
    },
    
    # ========================================================
    # AML.CS0035
    # Data Exfiltration from Slack AI via
    # Indirect Prompt Injection
    # ========================================================

    "AML.CS0035": {

        "attacker_name":
            "AML_CS0035_Attacker",

        # S00 - AML.T0066
        "entry_point":
            "SlackMaliciousMessage:"
            "retrievalContentCrafting",

        "path": [

            # S01 - AML.T0065
            "SlackMaliciousMessage:"
            "llmPromptCrafting",

            # S02 - AML.T0012
            "SlackWorkspace:"
            "validAccounts",

            # S03 - AML.T0047
            "SlackAI:"
            "aiEnabledProductOrService",

            # S04 - AML.T0070
            "SlackAIRAG:"
            "ragPoisoning",

            # S05 - AML.T0051.001
            "SlackAIConversation:"
            "indirectPromptInjection",

            # S06 - AML.T0082
            "SlackAIRAG:"
            "ragCredentialHarvesting",

            # S07 - AML.T0077
            "SlackRenderedExfiltration:"
            "llmResponseRendering",
        ],

        "goal":
            "SlackRenderedExfiltration:"
            "llmResponseRendering",
    },
    
    # ========================================================
    # AML.CS0036
    # AIKatz: Attacking LLM Desktop Applications
    # ========================================================
    
    "AML.CS0036": {

        "attacker_name":
            "AML_CS0036_Attacker",

        # S00 - AML.T0012
        "entry_point":
            "AIKatzVictimDesktop:validAccounts",

        "path": [

            # S01 - AML.T0089
            "AIKatzVictimDesktop:processDiscovery",

            # S02 - AML.T0090
            "AIKatzVictimDesktop:oSCredentialDumping",

            # S03 - AML.T0091.000
            "AIKatzLLMBackend:applicationAccessToken",

            # S04 - AML.T0047
            "AIKatzLLMApplication:aiEnabledProductOrService",

            # S05 - AML.T0051.000
            "AIKatzLLMApplication:directPromptInjection",

            # S06 - AML.T0080.001
            "AIKatzAgentContext:contextPoisoningThread",

            # S07 - AML.T0080.000
            "AIKatzAgentContext:contextPoisoningMemory",

            # S08 - AML.T0092
            "AIKatzConversation:manipulateUserLLMChatHistory",

            # Impact - AML.T0048.003
            "AIKatzExternalImpact:userHarm",
        ],

        "goal":
            "AIKatzExternalImpact:userHarm",
    },
    
    "AML.CS0036-FINANCIAL": {

        "attacker_name":
            "AML_CS0036_FINANCIAL_Attacker",

        "entry_point":
            "AIKatzVictimDesktop:validAccounts",

        "path": [
            "AIKatzVictimDesktop:processDiscovery",
            "AIKatzVictimDesktop:oSCredentialDumping",
            "AIKatzLLMBackend:applicationAccessToken",
            "AIKatzLLMApplication:aiEnabledProductOrService",
            "AIKatzLLMApplication:directPromptInjection",
            "AIKatzAgentContext:contextPoisoningThread",
            "AIKatzAgentContext:contextPoisoningMemory",
            "AIKatzConversation:manipulateUserLLMChatHistory",
            "AIKatzExternalImpact:financialHarm",
        ],

        "goal":
            "AIKatzExternalImpact:financialHarm",
    },
        
    "AML.CS0036-DOS": {

        "attacker_name":
            "AML_CS0036_DOS_Attacker",

        "entry_point":
            "AIKatzVictimDesktop:validAccounts",

        "path": [
            "AIKatzVictimDesktop:processDiscovery",
            "AIKatzVictimDesktop:oSCredentialDumping",
            "AIKatzLLMBackend:applicationAccessToken",
            "AIKatzLLMApplication:aiEnabledProductOrService",
            "AIKatzLLMApplication:directPromptInjection",
            "AIKatzAgentContext:contextPoisoningThread",
            "AIKatzAgentContext:contextPoisoningMemory",
            "AIKatzConversation:manipulateUserLLMChatHistory",
            "AIKatzServiceImpact:denialOfAIService",
        ],

        "goal":
            "AIKatzServiceImpact:denialOfAIService",
    },
    
    # ========================================================
    # AML.CS0037
    # Data Exfiltration via Agent Tools in Copilot Studio
    # ========================================================

    "AML.CS0037": {

        "attacker_name":
            "AML_CS0037_Attacker",

        # S00 - AML.T0006.003
        "entry_point":
            "CS0037AgentRecon:"
            "probeAIAgentTriggerChannels",

        "path": [

            # S01 - AML.T0065
            "CS0037ProbePrompt:"
            "llmPromptCrafting",

            # S02 - AML.T0093
            "CS0037CopilotAgent:"
            "promptInfiltrationViaPublicFacingApplication",

            # S03 - AML.T0051.002
            "CS0037TriggeredConversation:"
            "triggeredPromptInjection",

            # S04 - AML.T0084.002
            "CS0037TriggerConfiguration:"
            "activationTriggers",

            # S05 - AML.T0084.001
            "CS0037TriggerConfiguration:"
            "toolDefinitions",

            # S06 - AML.T0047
            "CS0037CopilotAgent:"
            "aiEnabledProductOrService",

            # S07 - AML.T0051
            "CS0037DiscoveryConversation:"
            "llmPromptInjection",

            # S08 - AML.T0084.000
            "CS0037DataConfiguration:"
            "embeddedKnowledge",

            # S09 - AML.T0084.001
            "CS0037DataConfiguration:"
            "toolDefinitions",

            # S10 - AML.T0065
            "CS0037ExfiltrationPrompt:"
            "llmPromptCrafting",

            # S11 - AML.T0085.000
            "CS0037CustomerSupportRAG:"
            "ragDatabases",

            # S12 - AML.T0085.001
            "CS0037SalesforceTool:"
            "aiAgentTools",

            # S13 - AML.T0086
            "CS0037EmailTool:"
            "exfiltrationViaAIAgentToolInvocation",
        ],

        "goal":
            "CS0037EmailTool:"
            "exfiltrationViaAIAgentToolInvocation",
    },
    
    # ========================================================
    # AML.CS0038
    # Planting Instructions for Delayed Automatic
    # AI Agent Tool Invocation
    # ========================================================

    "AML.CS0038": {

        "attacker_name":
            "AML_CS0038_Attacker",

        # S00 - AML.T0065
        "entry_point":
            "CS0038DelayedPrompt:"
            "llmPromptCrafting",

        "path": [

            # S01 - AML.T0093
            "CS0038Gemini:"
            "promptInfiltrationViaPublicFacingApplication",

            # S02 - AML.T0051.001
            "CS0038GeminiConversation:"
            "indirectPromptInjection",

            # S03 - AML.T0094
            "CS0038GeminiConversation:"
            "delayExecutionOfLLMInstructions",

            # S04 - AML.T0053
            "CS0038WorkspaceExtension:"
            "aiAgentToolInvocation",

            # S05 - AML.T0085.001
            "CS0038WorkspaceExtension:"
            "aiAgentTools",
        ],

        "goal":
            "CS0038WorkspaceExtension:"
            "aiAgentTools",
    },
    
    # ========================================================
    # AML.CS0039
    # Living Off AI: Prompt Injection via
    # Jira Service Management
    # ========================================================

    "AML.CS0039": {

        "attacker_name":
            "AML_CS0039_Attacker",

        # S00 - AML.T0003
        "entry_point":
            "CS0039Recon:"
            "searchVictimOwnedWebsites",

        "path": [

            # S01 - AML.T0095
            "CS0039Recon:"
            "searchOpenWebsitesDomains",

            # S02 - AML.T0065
            "CS0039MaliciousPrompt:"
            "llmPromptCrafting",

            # S03 - AML.T0093
            "CS0039JSMApplication:"
            "promptInfiltrationViaPublicFacingApplication",

            # S04 - AML.T0051.001
            "CS0039Conversation:"
            "indirectPromptInjection",

            # S05 - AML.T0053
            "CS0039AtlassianDataTool:"
            "aiAgentToolInvocation",

            # S06 - AML.T0085.001
            "CS0039AtlassianDataTool:"
            "aiAgentTools",

            # S07 - AML.T0086
            "CS0039AtlassianExfiltrationTool:"
            "exfiltrationViaAIAgentToolInvocation",
        ],

        "goal":
            "CS0039AtlassianExfiltrationTool:"
            "exfiltrationViaAIAgentToolInvocation",
    },
        
    # ========================================================
    # AML.CS0040
    # Hacking ChatGPT's Memories with Prompt Injection
    # ========================================================

    "AML.CS0040": {

        "attacker_name":
            "AML_CS0040_Attacker",

        # S00 - AML.T0065
        "entry_point":
            "CS0040MemoryPoisoningPrompt:"
            "llmPromptCrafting",

        "path": [

            # S01 - AML.T0068
            "CS0040MemoryPoisoningPrompt:"
            "llmPromptObfuscation",

            # S02 - AML.T0093
            "CS0040InitialPromptInfiltration:"
            "promptInfiltrationViaPublicFacingApplication",

            # S03 - AML.T0051.001
            "CS0040Conversation:"
            "indirectPromptInjection",

            # S04 - AML.T0080.000
            "CS0040MemoryContext:"
            "contextPoisoningMemory",

            # S05 - AML.T0093
            "CS0040PersistentPromptInfiltration:"
            "promptInfiltrationViaPublicFacingApplication",

            # S06 - AML.T0048.003
            "CS0040UserImpact:"
            "userHarm",
        ],

        "goal":
            "CS0040UserImpact:"
            "userHarm",
    },
    
    # ========================================================
    # AML.CS0041
    # Rules File Backdoor: Supply Chain Attack on
    # AI Coding Assistants
    # ========================================================

    "AML.CS0041": {

        "attacker_name":
            "AML_CS0041_Attacker",

        # S00 - AML.T0079
        "entry_point":
            "CS0041StagedCapability:"
            "stageCapabilities",

        "path": [

            # S01 - AML.T0065
            "CS0041RulesPrompt:"
            "llmPromptCrafting",

            # S02 - AML.T0068
            "CS0041RulesPrompt:"
            "llmPromptObfuscation",

            # S03 - AML.T0010.001
            "CS0041PoisonedRulesSoftware:"
            "aiSupplyChainCompromiseSoftware",

            # S04 - AML.T0081
            "CS0041AgentConfiguration:"
            "modifyAIAgentConfiguration",

            # S05 - AML.T0143
            "CS0041RulesPropagation:"
            "llmPromptPropagation",

            # S06 - AML.T0051.000
            "CS0041CodingAssistant:"
            "directPromptInjection",

            # S07 - AML.T0054
            "CS0041CodingConversation:"
            "llmJailbreak",

            # S08 - AML.T0067
            "CS0041TrustedOutput:"
            "trustedOutputComponentsManipulation",

            # S09 - AML.T0048.003
            "CS0041UserImpact:"
            "userHarm",
        ],

        "goal":
            "CS0041UserImpact:"
            "userHarm",
    },

}


# ============================================================
# CREATE MAL MODEL
# ============================================================

def create_model(lang_graph: LanguageGraph) -> Model:

    model = Model(
        "MITRE_ATLAS_CASE_STUDIES",
        lang_graph
    )


    # ========================================================
    # AML.CS0062
    # ========================================================

    malicious_prompt = model.add_asset(
        "LLMPrompt",
        "MaliciousPrompt"
    )

    semantic_kernel_agent = model.add_asset(
        "AIAgent",
        "SemanticKernelAgent"
    )

    search_plugin = model.add_asset(
        "AITool",
        "SearchPlugin"
    )

    vector_store = model.add_asset(
        "VectorStore",
        "InMemoryVectorStore"
    )

    host_os = model.add_asset(
        "OS",
        "HostOS"
    )

    host_computer = model.add_asset(
        "Computer",
        "SemanticKernelHost"
    )


    # --------------------------------------------------------
    # CS0062 associations
    # --------------------------------------------------------

    malicious_prompt.add_associated_assets(
        "aiAgent",
        {semantic_kernel_agent}
    )

    semantic_kernel_agent.add_associated_assets(
        "tool",
        {search_plugin}
    )

    search_plugin.add_associated_assets(
        "vectorStore",
        {vector_store}
    )

    vector_store.add_associated_assets(
        "os",
        {host_os}
    )

    host_computer.add_associated_assets(
        "os",
        {host_os}
    )


    # ========================================================
    # AML.CS0000
    # ========================================================

    preprint_repository = model.add_asset(
        "AIResearchMaterial",
        "PublicPrePrintRepository"
    )

    c2_dataset = model.add_asset(
        "TrainingData",
        "PublicC2Dataset"
    )

    proxy_detector = model.add_asset(
        "ProxyAIModel",
        "ProxyC2Detector"
    )

    adversarial_http_sample = model.add_asset(
        "AdversarialSample",
        "AdversarialHTTPSample"
    )

    production_c2_detector = model.add_asset(
        "AIMalwareDetector",
        "ProductionC2Detector"
    )


    # --------------------------------------------------------
    # CS0000 associations
    # --------------------------------------------------------

    preprint_repository.add_associated_assets(
        "trainingData",
        {c2_dataset}
    )

    c2_dataset.add_associated_assets(
        "proxyModel",
        {proxy_detector}
    )

    proxy_detector.add_associated_assets(
        "adversarialSample",
        {adversarial_http_sample}
    )

    adversarial_http_sample.add_associated_assets(
        "targetModel",
        {production_c2_detector}
    )


    # ========================================================
    # AML.CS0001
    # Botnet DGA Detection Evasion
    # ========================================================

    dga_research_sources = model.add_asset(
        "AIResearchMaterial",
        "DGAResearchSources"
    )

    public_dga_artifacts = model.add_asset(
        "PublicAIArtifacts",
        "PublicDGAAIArtifacts"
    )

    dga_mutation_capability = model.add_asset(
        "AdversarialCapability",
        "DGAMutationCapability"
    )

    mutated_dga_domains = model.add_asset(
        "AdversarialSample",
        "MutatedDGADomains"
    )

    production_dga_detector = model.add_asset(
        "AIMalwareDetector",
        "ProductionDGADetector"
    )


    # --------------------------------------------------------
    # CS0001 associations
    # --------------------------------------------------------

    # S00 -> S01
    # Search Open Technical Databases
    #       ->
    # Acquire Public AI Artifacts
    dga_research_sources.add_associated_assets(
        "publicArtifacts",
        {public_dga_artifacts}
    )

    # S01 -> S02
    # Acquire Public AI Artifacts
    #       ->
    # Adversarial AI Attacks
    public_dga_artifacts.add_associated_assets(
        "capability",
        {dga_mutation_capability}
    )

    # S02 -> S03
    # Develop adversarial capability
    #       ->
    # Black-Box Optimization
    dga_mutation_capability.add_associated_assets(
        "generatedSample",
        {mutated_dga_domains}
    )

    # S03 -> S04
    # Black-Box Optimization
    #       ->
    # Verify Attack
    mutated_dga_domains.add_associated_assets(
        "targetModel",
        {production_dga_detector}
    )
    
    # ========================================================
    # AML.CS0002
    # VirusTotal Poisoning
    # ========================================================

    metame_tool = model.add_asset(
        "AdversarialAttackImplementation",
        "MetameTool"
    )

    ransomware_variants = model.add_asset(
       "AdversarialSample",
       "MetamorphicRansomwareVariants"
    )

    virustotal_supply_chain = model.add_asset(
       "AISupplyChainData",
       "VirusTotalDataSupplyChain"
    )

    # IMPORTANT:
    # Reuse the existing TrainingData MAL asset
    virustotal_training_data = model.add_asset(
      "TrainingData",
     "VirusTotalTrainingData"
    )


    # --------------------------------------------------------
    # AML.CS0002 associations
    # --------------------------------------------------------

    # AML.T0016.000 -> AML.T0043
    metame_tool.add_associated_assets(
        "adversarialSample",
        {ransomware_variants}
    )

    # AML.T0043 -> AML.T0010.002
    ransomware_variants.add_associated_assets(
        "dataSupplyChain",
        {virustotal_supply_chain}
    )

    # AML.T0010.002 -> AML.T0020
    virustotal_supply_chain.add_associated_assets(
        "trainingData",
        {virustotal_training_data}
    )
    
    # ========================================================
    # AML.CS0003
    # Bypassing Cylance's AI Malware Detection
    # ========================================================

    cylance_research = model.add_asset(
        "AIResearchMaterial",
        "CylanceResearch"
    )

    cylance_detector = model.add_asset(
        "AIMalwareDetector",
        "CylanceMalwareDetector"
    )

    cylance_capability = model.add_asset(
        "AdversarialCapability",
        "CylanceBypassCapability"
    )

    cylance_adversarial_malware = model.add_asset(
        "AdversarialSample",
        "CylanceBypassMalware"
    )


    # --------------------------------------------------------
    # AML.CS0003 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0047
    cylance_research.add_associated_assets(
        "targetProduct",
        {cylance_detector}
    )

    # AML.T0063 -> AML.T0017.000
    cylance_detector.add_associated_assets(
        "capability",
        {cylance_capability}
    )

    # AML.T0017.000 -> AML.T0043.003
    cylance_capability.add_associated_assets(
        "manualSample",
        {cylance_adversarial_malware}
    )

    # AML.T0043.003 -> AML.T0015
    cylance_adversarial_malware.add_associated_assets(
        "evasionTarget",
        {cylance_detector}
    )
    
    # ========================================================
    # AML.CS0004
    # Camera Hijack Attack on Facial Recognition System
    #========================================================

    victim_identity = model.add_asset(
        "VictimIdentityInformation",
        "BlackMarketVictimIdentity"
    )

    consumer_phone = model.add_asset(
        "AIConsumerHardware",
        "CustomizedAndroidPhone"
    )

    camera_hijack_implementation = model.add_asset(
        "AdversarialAttackImplementation",
        "CameraHijackImplementation"
    )

    virtual_camera_tools = model.add_asset(
        "AIAttackSoftwareTool",
        "VirtualCameraToolset"
    )

    fraudulent_account = model.add_asset(
        "FraudulentAccount",
        "VictimImpersonationAccount"
    )

    facial_recognition_system = model.add_asset(
        "FacialRecognitionSystem",
        "TaxFacialRecognitionSystem"
    )

    financial_impact = model.add_asset(
        "ExternalHarm",
        "TaxFraudImpact"
    )


    # --------------------------------------------------------
    # AML.CS0004 associations
    # --------------------------------------------------------

    # AML.T0087 -> AML.T0008.001
    victim_identity.add_associated_assets(
        "hardware",
        {consumer_phone}
    )

    # AML.T0008.001 -> AML.T0016.000
    consumer_phone.add_associated_assets(
        "attackImplementation",
        {camera_hijack_implementation}
    )

    # AML.T0016.000 -> AML.T0016.001
    camera_hijack_implementation.add_associated_assets(
        "softwareTool",
        {virtual_camera_tools}
    )

    # AML.T0016.001 -> AML.T0021
    virtual_camera_tools.add_associated_assets(
        "account",
        {fraudulent_account}
    )

    # AML.T0021 -> AML.T0047
    fraudulent_account.add_associated_assets(
        "targetSystem",
        {facial_recognition_system}
    )

    # AML.T0015 -> AML.T0048.000
    facial_recognition_system.add_associated_assets(
       "impact",
       {financial_impact}
    )

    # ========================================================
    # AML.CS0005
    # Attack on Machine Translation Services
    # ========================================================

    translation_research = model.add_asset(
        "AIResearchMaterial",
        "TranslationResearchPapers"
    )

    translation_datasets = model.add_asset(
        "TrainingData",
        "PublicTranslationDatasets"
    )

    translation_models = model.add_asset(
        "PublicAIArtifacts",
        "PublicTranslationModels"
    )

    translation_service = model.add_asset(
        "MachineTranslationService",
        "ProductionTranslationService"
    )

    replicated_translation_model = model.add_asset(
        "ProxyAIModel",
        "ReplicatedTranslationModel"
    )

    translation_ip_theft = model.add_asset(
        "ExternalHarm",
        "TranslationModelIPTheft"
    )

    transferred_adversarial_sentences = model.add_asset(
        "AdversarialSample",
        "TransferredAdversarialSentences"
    )


    # --------------------------------------------------------
    # CS0005 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0002.000
    # Search research papers -> acquire public datasets
    translation_research.add_associated_assets(
        "trainingData",
        {translation_datasets}
    )

    # AML.T0002.000 -> AML.T0002.001
    # Public datasets -> public model architectures
    translation_datasets.add_associated_assets(
        "publicArtifacts",
        {translation_models}
    )

    # AML.T0002.001 -> AML.T0040
    # Public model artifacts -> query the production service
    translation_models.add_associated_assets(
        "targetService",
        {translation_service}
    )

    # AML.T0040 -> AML.T0005.001
    # Inference API access -> train replica from query results
    translation_service.add_associated_assets(
        "proxyModel",
        {replicated_translation_model}
    )

    # AML.T0005.001 -> AML.T0048.004
    # Functionally replicated model -> IP theft
    replicated_translation_model.add_associated_assets(
        "externalHarm",
        {translation_ip_theft}
    )

    # AML.T0048.004 -> AML.T0043.002
    # Stolen/replicated model -> craft transfer adversarial data
    translation_ip_theft.add_associated_assets(
        "adversarialSample",
        {transferred_adversarial_sentences}
    )

    # AML.T0043.002 -> AML.T0015 -> AML.T0031
    # Transfer adversarial inputs -> evade -> erode integrity
    transferred_adversarial_sentences.add_associated_assets(
        "targetService",
        {translation_service}
    )
    
    # ========================================================
    # AML.CS0006
    # ClearviewAI Misconfiguration
    # ========================================================

    # AML.T0021 - Establish Accounts
    clearview_repository_account = model.add_asset(
        "FraudulentAccount",
        "ClearviewRepositoryAccount"
    )

    # AML.T0036 / ATT&CK T1213
    # Data from Information Repositories
    clearview_repository_os = model.add_asset(
        "AIRepositoryOS",
        "ClearviewRepositoryOS"
    )

    # AML.T0002 - Acquire Public AI Artifacts
    clearview_public_artifacts = model.add_asset(
        "PublicAIArtifacts",
        "ClearviewPublicAIArtifacts"
    )

    # AML.T0031 - Erode AI Model Integrity
    clearview_facial_recognition_system = model.add_asset(
        "FacialRecognitionSystem",
        "ClearviewFacialRecognitionSystem"
    )


    # --------------------------------------------------------
    # CS0006 associations
    # --------------------------------------------------------

    # AML.T0021 -> AML.T0036
    clearview_repository_account.add_associated_assets(
        "repositoryOS",
        {clearview_repository_os}
    )

    # AML.T0036 -> AML.T0002
    clearview_repository_os.add_associated_assets(
        "publicArtifacts",
        {clearview_public_artifacts}
    )

    # AML.T0002 -> AML.T0031
    clearview_public_artifacts.add_associated_assets(
        "integrityTarget",
        {clearview_facial_recognition_system}
    )
    
    # ========================================================
    # AML.CS0007
    # GPT-2 Model Replication
    # ========================================================

    gpt2_research = model.add_asset(
        "AIResearchMaterial",
        "GPT2Research"
    )

    gpt2_dataset = model.add_asset(
        "TrainingData",
        "GPT2TrainingDataset"
    )

    grover_model = model.add_asset(
        "PublicAIArtifacts",
        "PublicGroverModel"
    )

    gpt2_workspace = model.add_asset(
        "AIDevelopmentWorkspace",
        "GPT2ReplicationWorkspace"
    )

    replicated_gpt2 = model.add_asset(
        "ProxyAIModel",
        "ReplicatedGPT2Model"
    )
    
    # --------------------------------------------------------
    # CS0007 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0002.000
    gpt2_research.add_associated_assets(
        "trainingData",
        {gpt2_dataset}
    )

    # AML.T0002.000 -> AML.T0002.001
    gpt2_dataset.add_associated_assets(
        "publicArtifacts",
        {grover_model}
    )

    # AML.T0002.001 -> AML.T0008.000
    grover_model.add_associated_assets(
        "developmentWorkspace",
        {gpt2_workspace}
    )

    # AML.T0008.000 -> AML.T0005.000
    gpt2_workspace.add_associated_assets(
        "proxyModel",
        {replicated_gpt2}
    )
    
    # ========================================================
    # AML.CS0008
    # ProofPoint Evasion
    # ========================================================

    proofpoint_detector = model.add_asset(
        "AIMalwareDetector",
        "ProofPointEmailProtection"
    )

    proofpoint_proxy = model.add_asset(
        "ProxyAIModel",
        "ProofPointShadowModel"
    )

    proofpoint_adversarial_email = model.add_asset(
        "AdversarialSample",
        "ProofPointAdversarialEmail"
    )
    
    # --------------------------------------------------------
    # CS0008 associations
    # --------------------------------------------------------

    # AML.T0063 -> AML.T0005.001
    proofpoint_detector.add_associated_assets(
        "proxyModel",
        {proofpoint_proxy}
    )

    # AML.T0005.001 -> AML.T0043.002
    proofpoint_proxy.add_associated_assets(
        "adversarialSample",
        {proofpoint_adversarial_email}
    )

    # AML.T0043.002 -> AML.T0015
    proofpoint_adversarial_email.add_associated_assets(
        "evasionTarget",
        {proofpoint_detector}
    )
    
    # ========================================================
    # AML.CS0009
    # Tay Poisoning
    # ========================================================

    tay_chatbot = model.add_asset(
        "OnlineLearningAIModel",
        "TayChatbot"
    )

    tay_supply_chain = model.add_asset(
        "AISupplyChainData",
        "TayConversationSupplyChain"
    )

    tay_training_data = model.add_asset(
        "TrainingData",
        "TayOnlineTrainingData"
    )
    
    # --------------------------------------------------------
    # CS0009 associations
    # --------------------------------------------------------

    # AML.T0047 -> AML.T0010.002
    tay_chatbot.add_associated_assets(
        "poisoningSupplyChain",
        {tay_supply_chain}
    )

    # AML.T0010.002 -> AML.T0020
    tay_supply_chain.add_associated_assets(
        "trainingData",
        {tay_training_data}
    )

    # AML.T0020 -> AML.T0031
    tay_training_data.add_associated_assets(
        "integrityTarget",
        {tay_chatbot}
    )
    
    # ========================================================
    # AML.CS0010
    # Microsoft Azure Service Disruption
    # ========================================================

    azure_research = model.add_asset(
        "AIResearchMaterial",
        "AzureResearch"
    )

    azure_service_os = model.add_asset(
        "AIServiceOS",
        "AzureServiceOS"
    )

    azure_artifact_collection = model.add_asset(
        "AIArtifactCollection",
        "AzureArtifactCollection"
    )

    azure_exfiltration = model.add_asset(
        "AIExfiltration",
        "AzureArtifactExfiltration"
    )

    azure_adversarial_example = model.add_asset(
        "AdversarialSample",
        "AzureAdversarialExample"
    )

    azure_target_service = model.add_asset(
        "AIInferenceService",
        "AzureTargetService"
    )
    
    # --------------------------------------------------------
    # CS0010 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0012 / T1078
    azure_research.add_associated_assets(
        "targetOS",
        {azure_service_os}
    )

    # AML.T0012 -> AML.T0035
    azure_service_os.add_associated_assets(
        "artifactCollection",
        {azure_artifact_collection}
    )

    # AML.T0035 -> AML.T0025
    azure_artifact_collection.add_associated_assets(
        "exfiltration",
        {azure_exfiltration}
    )

    # AML.T0025 -> AML.T0043.000
    azure_exfiltration.add_associated_assets(
        "adversarialSample",
        {azure_adversarial_example}
    )

    # AML.T0043.000 -> AML.T0040
    azure_adversarial_example.add_associated_assets(
        "inferenceTarget",
        {azure_target_service}
    )
    
    # ========================================================
    # AML.CS0011
    # Microsoft Edge AI Evasion
    # ========================================================

    edge_research = model.add_asset(
        "AIResearchMaterial",
        "EdgeAIResearch"
    )

    edge_public_artifacts = model.add_asset(
        "PublicAIArtifacts",
        "EdgePublicBaseModel"
    )

    edge_public_inference = model.add_asset(
        "AIInferenceService",
        "EdgePublicInferenceService"
    )

    edge_adversarial_image = model.add_asset(
        "AdversarialSample",
        "EdgeAdversarialImage"
    )

    edge_target_model = model.add_asset(
        "PredictiveAIModel",
        "MicrosoftEdgeTargetModel"
    )
    
    # --------------------------------------------------------
    # CS0011 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0002
    edge_research.add_associated_assets(
        "publicArtifacts",
        {edge_public_artifacts}
    )

    # AML.T0002 -> AML.T0040
    edge_public_artifacts.add_associated_assets(
        "inferenceService",
        {edge_public_inference}
    )

    # AML.T0040 -> AML.T0043.001
    edge_public_inference.add_associated_assets(
        "blackBoxSample",
        {edge_adversarial_image}
    )

    # AML.T0043.001 -> AML.T0015
    edge_adversarial_image.add_associated_assets(
        "edgeEvasionTarget",
        {edge_target_model}
    )
    
    # ========================================================
    # AML.CS0012
    # Face Identification System Evasion
    # ========================================================

    face_id_research = model.add_asset(
        "AIResearchMaterial",
        "FaceIDResearch"
    )

    face_id_service_os = model.add_asset(
        "AIServiceOS",
        "FaceIDServiceOS"
    )

    face_id_service = model.add_asset(
        "AIInferenceService",
        "CommercialFaceIDService"
    )

    face_dataset = model.add_asset(
        "TrainingData",
        "PublicFaceDataset"
    )

    face_proxy_model = model.add_asset(
        "ProxyAIModel",
        "FaceIDProxyModel"
    )

    optimized_face_pattern = model.add_asset(
        "AdversarialSample",
        "OptimizedFacePattern"
    )

    printed_sticker = model.add_asset(
        "PhysicalCountermeasure",
        "PrintedAdversarialSticker"
    )

    face_environment = model.add_asset(
        "PhysicalAIEnvironment",
        "FaceCaptureEnvironment"
    )
    
    # --------------------------------------------------------
    # CS0012 associations
    # --------------------------------------------------------

    # AML.T0000 -> AML.T0012
    face_id_research.add_associated_assets(
        "targetOS",
        {face_id_service_os}
    )

    # AML.T0012 -> AML.T0040
    face_id_service_os.add_associated_assets(
        "inferenceService",
        {face_id_service}
    )

    # AML.T0013 -> AML.T0002.000
    face_id_service.add_associated_assets(
        "ontologyData",
        {face_dataset}
    )

    # AML.T0002.000 -> AML.T0005
    face_dataset.add_associated_assets(
        "proxyModel",
        {face_proxy_model}
    )

    # AML.T0005 -> AML.T0043.000
    face_proxy_model.add_associated_assets(
        "adversarialSample",
        {optimized_face_pattern}
    )

    # AML.T0043.000 -> AML.T0008.003
    optimized_face_pattern.add_associated_assets(
        "physicalCountermeasure",
        {printed_sticker}
    )

    # AML.T0008.003 -> AML.T0041
    printed_sticker.add_associated_assets(
        "physicalEnvironment",
        {face_environment}
    )

    # AML.T0041 -> AML.T0015
    face_environment.add_associated_assets(
        "targetModel",
        {face_id_service}
    )
    
    # ========================================================
    # AML.CS0013
    # Backdoor Attack on Deep Learning Models in Mobile Apps
    # ========================================================

    mobile_repository_research = model.add_asset(
        "AIResearchMaterial",
        "MobileAppRepositoryResearch"
    )

    downloaded_mobile_model = model.add_asset(
        "PublicAIArtifacts",
        "DownloadedMobileModel"
    )

    target_mobile_model = model.add_asset(
        "MobileAIModel",
        "TargetMobileAIModel"
    )

    neural_payload_capability = model.add_asset(
        "AdversarialCapability",
        "NeuralPayloadCapability"
    )

    mobile_model_supply_chain = model.add_asset(
        "AISupplyChainModel",
        "CompromisedMobileModelSupplyChain"
    )

    backdoor_trigger = model.add_asset(
        "BackdoorTrigger",
        "VisualBackdoorTrigger"
    )

    victim_physical_environment = model.add_asset(
        "PhysicalAIEnvironment",
        "VictimPhysicalEnvironment"
    )
    
    # --------------------------------------------------------
    # CS0013 associations
    # --------------------------------------------------------

    # AML.T0004 -> AML.T0002.001
    mobile_repository_research.add_associated_assets(
        "publicArtifacts",
        {downloaded_mobile_model}
    )

    # AML.T0002.001 -> AML.T0044
    downloaded_mobile_model.add_associated_assets(
        "fullAccessTarget",
        {target_mobile_model}
    )

    # AML.T0044 -> AML.T0017.000
    target_mobile_model.add_associated_assets(
        "capability",
        {neural_payload_capability}
    )

    # AML.T0017.000 -> AML.T0018.001
    neural_payload_capability.add_associated_assets(
        "modifiedModel",
        {target_mobile_model}
    )

    # AML.T0042 -> AML.T0010.003
    target_mobile_model.add_associated_assets(
        "modelSupplyChain",
        {mobile_model_supply_chain}
    )

    # AML.T0010.003 -> AML.T0043.004
    mobile_model_supply_chain.add_associated_assets(
        "trigger",
        {backdoor_trigger}
    )

    # AML.T0043.004 -> AML.T0041
    backdoor_trigger.add_associated_assets(
        "physicalEnvironment",
        {victim_physical_environment}
    )

    # AML.T0041 -> AML.T0015
    victim_physical_environment.add_associated_assets(
        "targetModel",
        {target_mobile_model}
    )
    
    # ========================================================
    # AML.CS0014
    # Confusing Antimalware Neural Networks
    # ========================================================

    kaspersky_research = model.add_asset(
        "AIResearchMaterial",
        "KasperskyGrayBoxResearch"
    )

    kaspersky_detector = model.add_asset(
        "AIMalwareDetector",
        "KasperskyAntimalwareModel"
    )

    kaspersky_dataset = model.add_asset(
        "TrainingData",
        "KasperskyLabeledDataset"
    )

    kaspersky_proxy = model.add_asset(
        "ProxyAIModel",
        "KasperskyProxyModel"
    )

    kaspersky_capability = model.add_asset(
        "AdversarialCapability",
        "KasperskyAdversarialCapability"
    )

    kaspersky_adversarial_malware = model.add_asset(
        "AdversarialSample",
        "KasperskyAdversarialMalware"
    )
    
    # --------------------------------------------------------
    # CS0014 associations
    # --------------------------------------------------------

    # AML.T0003 -> AML.T0047
    kaspersky_research.add_associated_assets(
        "targetProduct",
        {kaspersky_detector}
    )

    # AML.T0047 -> AML.T0002.000
    kaspersky_detector.add_associated_assets(
        "labeledDataset",
        {kaspersky_dataset}
    )

    # AML.T0002.000 -> AML.T0005
    kaspersky_dataset.add_associated_assets(
        "proxyModel",
        {kaspersky_proxy}
    )

    # AML.T0005 -> AML.T0017.000
    kaspersky_proxy.add_associated_assets(
        "capability",
        {kaspersky_capability}
    )

    # AML.T0017.000 -> AML.T0043.002
    kaspersky_capability.add_associated_assets(
        "transferSample",
        {kaspersky_adversarial_malware}
    )

    # AML.T0043.002 -> AML.T0042
    kaspersky_adversarial_malware.add_associated_assets(
        "targetModel",
        {kaspersky_detector}
    )
    
    # ========================================================
    # AML.CS0015
    # Compromised PyTorch Dependency Chain
    # ========================================================

    compromised_torchtriton = model.add_asset(
        "AISupplyChainSoftware",
        "CompromisedTorchtritonPackage"
    )

    pytorch_victim_host = model.add_asset(
        "AISupplyChainHostOS",
        "PyTorchVictimHost"
    )

    pytorch_dns_exfiltration = model.add_asset(
        "AIExfiltration",
        "PyTorchDNSExfiltration"
    )
    
    # --------------------------------------------------------
    # CS0015 associations
    # --------------------------------------------------------

    # AML.T0010.001 -> AML.T0037
    compromised_torchtriton.add_associated_assets(
        "hostOS",
        {pytorch_victim_host}
    )

    # AML.T0037 -> AML.T0025
    pytorch_victim_host.add_associated_assets(
        "exfiltration",
        {pytorch_dns_exfiltration}
    )
    
    # ========================================================
    # AML.CS0016
    # Achieving Code Execution in MathGPT via Prompt Injection
    # ========================================================

    mathgpt_research = model.add_asset(
        "AIResearchMaterial",
        "MathGPTResearch"
    )

    mathgpt_application = model.add_asset(
        "PublicFacingLLMApplication",
        "MathGPTApplication"
    )

    mathgpt_python_interpreter = model.add_asset(
        "AITool",
        "MathGPTPythonInterpreter"
    )

    mathgpt_host = model.add_asset(
        "MathGPTHostOS",
        "MathGPTHost"
    )

    mathgpt_financial_impact = model.add_asset(
        "ExternalHarm",
        "MathGPTFinancialImpact"
    )

    mathgpt_service_impact = model.add_asset(
        "AIServiceImpact",
        "MathGPTServiceImpact"
    )
    
    # --------------------------------------------------------
    # CS0016 associations
    # --------------------------------------------------------

    # AML.T0001 -> AML.T0047
    mathgpt_research.add_associated_assets(
        "publicLLMApp",
        {mathgpt_application}
    )

    # AML.T0093 -> AML.T0053
    mathgpt_application.add_associated_assets(
        "tool",
        {mathgpt_python_interpreter}
    )

    # AML.T0053 -> AML.T0055
    mathgpt_python_interpreter.add_associated_assets(
        "hostOS",
        {mathgpt_host}
    )

    # AML.T0055 -> AML.T0048.000
    mathgpt_host.add_associated_assets(
        "impact",
        {mathgpt_financial_impact}
    )

    # AML.T0053 -> AML.T0029
    mathgpt_python_interpreter.add_associated_assets(
        "serviceImpact",
        {mathgpt_service_impact}
    )
    
    # ========================================================
    # AML.CS0017
    # Bypassing ID.me Identity Verification
    # ========================================================

    idme_verification_system = model.add_asset(
        "FacialRecognitionSystem",
        "IDMeIdentityVerificationSystem"
    )

    idme_financial_impact = model.add_asset(
        "ExternalHarm",
        "IDMeFraudImpact"
    )
    
    # --------------------------------------------------------
    # CS0017 associations
    # --------------------------------------------------------

    # AML.T0015 -> AML.T0048.000
    idme_verification_system.add_associated_assets(
        "impact",
        {idme_financial_impact}
    )
    
    # ========================================================
    # AML.CS0018
    # Arbitrary Code Execution with Google Colab
    # ========================================================

    colab_capability = model.add_asset(
        "AdversarialCapability",
        "ColabMaliciousNotebookCapability"
    )

    compromised_colab_notebook = model.add_asset(
        "AISupplyChainSoftware",
        "CompromisedColabNotebook"
    )

    colab_drive_access = model.add_asset(
        "AIServiceOS",
        "ColabDriveAccess"
    )

    colab_user_execution = model.add_asset(
        "AIUserExecution",
        "ColabNotebookExecution"
    )

    colab_artifact_collection = model.add_asset(
        "AIArtifactCollection",
        "ColabArtifactCollection"
    )

    colab_exfiltration = model.add_asset(
        "AIExfiltration",
        "ColabExfiltration"
    )

    colab_external_impact = model.add_asset(
        "ExternalHarm",
        "ColabExternalImpact"
    )
    
    # --------------------------------------------------------
    # CS0018 associations
    # --------------------------------------------------------

    # AML.T0017 -> AML.T0010.001
    colab_capability.add_associated_assets(
        "compromisedSoftware",
        {compromised_colab_notebook}
    )

    # AML.T0010.001 -> AML.T0012
    compromised_colab_notebook.add_associated_assets(
        "serviceOS",
        {colab_drive_access}
    )

    # AML.T0012 -> AML.T0011
    colab_drive_access.add_associated_assets(
        "userExecution",
        {colab_user_execution}
    )

    # AML.T0011 -> AML.T0035
    colab_user_execution.add_associated_assets(
        "artifactCollection",
        {colab_artifact_collection}
    )

    # AML.T0035 -> AML.T0025
    colab_artifact_collection.add_associated_assets(
        "exfiltration",
        {colab_exfiltration}
    )

    # AML.T0025 -> AML.T0048.004
    colab_exfiltration.add_associated_assets(
        "impact",
        {colab_external_impact}
    )
    
    # ========================================================
    # AML.CS0019
    # PoisonGPT
    # ========================================================

    public_gptj_model = model.add_asset(
        "PublicAIArtifacts",
        "PublicGPTJModel"
    )

    poisoned_gptj_model = model.add_asset(
        "PoisonableAIModel",
        "PoisonedGPTJModel"
    )

    poisoned_model_publisher = model.add_asset(
        "PoisonedAIModelPublisher",
        "HuggingFacePoisonedModelPublisher"
    )

    poisongpt_supply_chain = model.add_asset(
        "AISupplyChainModel",
        "PoisonGPTModelSupplyChain"
    )

    victim_poisongpt_model = model.add_asset(
        "PoisonableAIModel",
        "VictimPoisonGPTModel"
    )

    poisongpt_reputation_impact = model.add_asset(
        "ExternalHarm",
        "PoisonGPTReputationImpact"
    )
    
    # --------------------------------------------------------
    # CS0019 associations
    # --------------------------------------------------------

    # AML.T0002.001 -> AML.T0018.000
    public_gptj_model.add_associated_assets(
        "poisonTarget",
        {poisoned_gptj_model}
    )

    # AML.T0042 -> AML.T0115.001
    poisoned_gptj_model.add_associated_assets(
        "publisher",
        {poisoned_model_publisher}
    )

    # AML.T0115.001 -> AML.T0010.003
    poisoned_model_publisher.add_associated_assets(
        "modelSupplyChain",
        {poisongpt_supply_chain}
    )

    # AML.T0010.003 -> AML.T0031
    poisongpt_supply_chain.add_associated_assets(
        "integrityTarget",
        {victim_poisongpt_model}
    )

    # AML.T0031 -> AML.T0048.001
    victim_poisongpt_model.add_associated_assets(
        "impact",
        {poisongpt_reputation_impact}
    )
    
    # ========================================================
    # AML.CS0020
    # Bing Chat Data Pirate
    # ========================================================

    bing_capability = model.add_asset(
        "AdversarialCapability",
        "BingDataPirateCapability"
    )

    bing_hidden_prompt = model.add_asset(
        "LLMPrompt",
        "BingHiddenPrompt"
    )

    bing_conversation = model.add_asset(
        "LLMConversation",
        "BingChatConversation"
    )

    bing_social_engineering = model.add_asset(
        "SocialEngineeringLLM",
        "BingSocialEngineering"
    )

    bing_user_impact = model.add_asset(
        "ExternalHarm",
        "BingUserImpact"
    )
    
    # --------------------------------------------------------
    # CS0020 associations
    # --------------------------------------------------------

    # AML.T0017 -> AML.T0068
    bing_capability.add_associated_assets(
        "obfuscatedPrompt",
        {bing_hidden_prompt}
    )

    # AML.T0068 -> AML.T0051.001
    bing_hidden_prompt.add_associated_assets(
        "indirectConversation",
        {bing_conversation}
    )

    # AML.T0051.001 -> AML.T0052.000
    bing_conversation.add_associated_assets(
        "socialEngineering",
        {bing_social_engineering}
    )

    # AML.T0052.000 -> AML.T0048.003
    bing_social_engineering.add_associated_assets(
        "externalHarm",
        {bing_user_impact}
    )
    
    # ========================================================
    # AML.CS0021
    # ChatGPT Conversation Exfiltration
    # ========================================================

    chatgpt_exfiltration_prompt = model.add_asset(
        "LLMPrompt",
        "ChatGPTExfiltrationPrompt"
    )

    chatgpt_staged_prompt = model.add_asset(
        "LLMStagedCapability",
        "ChatGPTStagedPrompt"
    )

    chatgpt_driveby_browser = model.add_asset(
        "LLMDriveByBrowser",
        "ChatGPTDriveByBrowser"
    )

    chatgpt_exfiltration_conversation = model.add_asset(
        "LLMConversation",
        "ChatGPTExfiltrationConversation"
    )

    chatgpt_browsing_plugin = model.add_asset(
        "AITool",
        "ChatGPTBrowsingPlugin"
    )

    chatgpt_rendered_exfiltration = model.add_asset(
        "LLMRenderedResponse",
        "ChatGPTRenderedExfiltration"
    )

    chatgpt_user_impact = model.add_asset(
        "ExternalHarm",
        "ChatGPTUserImpact"
    )
    
    # --------------------------------------------------------
    # CS0021 associations
    # --------------------------------------------------------

    # AML.T0065 -> AML.T0079
    chatgpt_exfiltration_prompt.add_associated_assets(
        "stagedCapability",
        {chatgpt_staged_prompt}
    )

    # AML.T0079 -> AML.T0078
    chatgpt_staged_prompt.add_associated_assets(
        "browser",
        {chatgpt_driveby_browser}
    )

    # AML.T0078 -> AML.T0051.001
    chatgpt_driveby_browser.add_associated_assets(
        "indirectConversation",
        {chatgpt_exfiltration_conversation}
    )

    # AML.T0051.001 -> AML.T0053
    chatgpt_exfiltration_conversation.add_associated_assets(
        "tool",
        {chatgpt_browsing_plugin}
    )

    # AML.T0053 -> AML.T0077
    chatgpt_browsing_plugin.add_associated_assets(
        "renderedResponse",
        {chatgpt_rendered_exfiltration}
    )

    # AML.T0077 -> AML.T0048.003
    chatgpt_rendered_exfiltration.add_associated_assets(
        "externalHarm",
        {chatgpt_user_impact}
    )
    
    # ========================================================
    # AML.CS0022
    # ChatGPT Package Hallucination
    # ========================================================

    chatgpt_package_service = model.add_asset(
        "AIInferenceService",
        "ChatGPTPackageService"
    )

    hallucinated_package_publisher = model.add_asset(
        "HallucinatedEntityPublisher",
        "HallucinatedPackagePublisher"
    )

    hallucinated_package_supply_chain = model.add_asset(
        "AISupplyChainSoftware",
        "HallucinatedPackageSupplyChain"
    )

    hallucinated_package_execution = model.add_asset(
        "AIUserExecution",
        "HallucinatedPackageExecution"
    )

    hallucinated_package_user_impact = model.add_asset(
        "ExternalHarm",
        "HallucinatedPackageUserImpact"
    )
    
    # --------------------------------------------------------
    # CS0022 associations
    # --------------------------------------------------------

    # AML.T0062 -> AML.T0060
    chatgpt_package_service.add_associated_assets(
        "hallucinatedPublisher",
        {hallucinated_package_publisher}
    )

    # AML.T0060 -> AML.T0010.001
    hallucinated_package_publisher.add_associated_assets(
        "compromisedSoftware",
        {hallucinated_package_supply_chain}
    )

    # AML.T0010.001 -> AML.T0011.001
    hallucinated_package_supply_chain.add_associated_assets(
        "userExecution",
        {hallucinated_package_execution}
    )

    # AML.T0011.001 -> AML.T0048.003
    hallucinated_package_execution.add_associated_assets(
        "externalHarm",
        {hallucinated_package_user_impact}
    )
    
    # ========================================================
    # AML.CS0023
    # ShadowRay
    # ========================================================

    shadowray_research = model.add_asset(
        "AIResearchMaterial",
        "ShadowRayResearch"
    )

    exposed_ray_cluster = model.add_asset(
        "RayClusterOS",
        "ExposedRayCluster"
    )

    shadowray_artifact_collection = model.add_asset(
        "AIArtifactCollection",
        "ShadowRayArtifactCollection"
    )

    shadowray_exfiltration = model.add_asset(
        "AIExfiltration",
        "ShadowRayExfiltration"
    )

    shadowray_model_supply_chain = model.add_asset(
        "AISupplyChainModel",
        "ShadowRayModelSupplyChain"
    )

    shadowray_financial_impact = model.add_asset(
        "ExternalHarm",
        "ShadowRayFinancialImpact"
    )
    
    # --------------------------------------------------------
    # CS0023 associations
    # --------------------------------------------------------

    # AML.T0006 -> AML.T0049
    shadowray_research.add_associated_assets(
        "targetCluster",
        {exposed_ray_cluster}
    )

    # AML.T0049 -> AML.T0035
    exposed_ray_cluster.add_associated_assets(
        "artifactCollection",
        {shadowray_artifact_collection}
    )

    # AML.T0035 -> AML.T0055
    shadowray_artifact_collection.add_associated_assets(
        "credentialHost",
        {exposed_ray_cluster}
    )

    # AML.T0055 -> AML.T0025
    exposed_ray_cluster.add_associated_assets(
        "exfiltration",
        {shadowray_exfiltration}
    )

    # AML.T0025 -> AML.T0010.003
    shadowray_exfiltration.add_associated_assets(
        "modelSupplyChain",
        {shadowray_model_supply_chain}
    )

    # AML.T0010.003 -> AML.T0048.000
    shadowray_model_supply_chain.add_associated_assets(
        "impact",
        {shadowray_financial_impact}
    )
    
    # ========================================================
    # AML.CS0024
    # Morris II Worm
    # ========================================================

    morris_model_service = model.add_asset(
        "AIInferenceService",
        "MorrisGenAIService"
    )

    morris_prompt = model.add_asset(
        "LLMPrompt",
        "MorrisAdversarialPrompt"
    )

    morris_email_application = model.add_asset(
        "PublicFacingLLMApplication",
        "MorrisEmailApplication"
    )

    morris_rag_database = model.add_asset(
        "RAGKnowledgeBase",
        "MorrisRAGDatabase"
    )

    morris_conversation = model.add_asset(
        "LLMConversation",
        "MorrisTriggeredConversation"
    )

    morris_prompt_propagation = model.add_asset(
        "LLMPromptPropagation",
        "MorrisPromptPropagation"
    )

    morris_exfiltration = model.add_asset(
        "AIExfiltration",
        "MorrisExfiltration"
    )

    morris_user_impact = model.add_asset(
        "ExternalHarm",
        "MorrisUserImpact"
    )
    
    # --------------------------------------------------------
    # CS0024 associations
    # --------------------------------------------------------

    # S00 -> S01
    # Reverse association also provides S01 -> S02
    morris_model_service.add_associated_assets(
        "craftedPrompt",
        {morris_prompt}
    )

    # S02 -> S03
    morris_model_service.add_associated_assets(
        "infiltrationTarget",
        {morris_email_application}
    )

    # S03 -> S04
    morris_email_application.add_associated_assets(
        "ragStore",
        {morris_rag_database}
    )

    # S04 -> S05
    # Reverse role also provides S06 -> S08
    morris_rag_database.add_associated_assets(
        "triggeredConversation",
        {morris_conversation}
    )

    # S06 -> S07
    morris_conversation.add_associated_assets(
        "selfReplicatingPrompt",
        {morris_prompt}
    )

    # S07 -> S10
    morris_prompt.add_associated_assets(
        "propagation",
        {morris_prompt_propagation}
    )

    # S08 -> S09
    morris_rag_database.add_associated_assets(
        "exfiltration",
        {morris_exfiltration}
    )

    # S09 -> S11
    # Reuses existing AIExfiltration <-> ExternalHarm association
    morris_exfiltration.add_associated_assets(
        "impact",
        {morris_user_impact}
    )
    
    # ========================================================
    # AML.CS0025
    # Web-Scale Data Poisoning: Split-View Attack
    # ========================================================

    web_scale_dataset = model.add_asset(
        "TrainingData",
        "WebScaleDataset"
    )

    expired_dataset_domains = model.add_asset(
        "AIDomainInfrastructure",
        "ExpiredDatasetDomains"
    )

    poisoned_web_scale_data = model.add_asset(
        "TrainingData",
        "PoisonedWebScaleData"
    )

    split_view_publisher = model.add_asset(
        "PoisonedDatasetPublisher",
        "SplitViewDatasetPublisher"
    )

    split_view_affected_model = model.add_asset(
        "PoisonableAIModel",
        "SplitViewAffectedModel"
    )
    
    # --------------------------------------------------------
    # CS0025 associations
    # --------------------------------------------------------

    # S00 -> S01
    web_scale_dataset.add_associated_assets(
        "domainInfrastructure",
        {expired_dataset_domains}
    )

    # S01 -> S02
    expired_dataset_domains.add_associated_assets(
        "poisonedData",
        {poisoned_web_scale_data}
    )

    # S02 -> S03
    poisoned_web_scale_data.add_associated_assets(
        "publisher",
        {split_view_publisher}
    )

    # S03 -> S04
    split_view_publisher.add_associated_assets(
        "targetDataset",
        {poisoned_web_scale_data}
    )

    # S04 -> S05
    poisoned_web_scale_data.add_associated_assets(
        "modelIntegrityTarget",
        {split_view_affected_model}
    )
    
    # ========================================================
    # AML.CS0026
    # Financial Transaction Hijacking with M365 Copilot
    # ========================================================

    m365_copilot_research = model.add_asset(
        "AIResearchMaterial",
        "M365CopilotResearch"
    )

    m365_copilot = model.add_asset(
        "PublicFacingLLMApplication",
        "M365Copilot"
    )

    m365_malicious_email = model.add_asset(
        "LLMPrompt",
        "M365MaliciousEmail"
    )

    m365_copilot_rag = model.add_asset(
        "RAGKnowledgeBase",
        "M365CopilotRAG"
    )

    m365_conversation = model.add_asset(
        "LLMConversation",
        "M365CopilotConversation"
    )

    m365_search_tool = model.add_asset(
        "AITool",
        "M365SearchEnterpriseTool"
    )

    m365_response = model.add_asset(
        "LLMRenderedResponse",
        "M365ManipulatedResponse"
    )

    m365_financial_impact = model.add_asset(
        "ExternalHarm",
        "M365FinancialImpact"
    )
    
    # --------------------------------------------------------
    # CS0026 associations
    # --------------------------------------------------------

    # S00 -> S01
    # Reuses existing AIResearchMaterial <-> PublicFacingLLMApplication
    m365_copilot_research.add_associated_assets(
        "publicLLMApp",
        {m365_copilot}
    )

    # Supports:
    # S03 -> S04
    # S05 -> S06
    # S06 -> S07
    m365_malicious_email.add_associated_assets(
        "targetApplication",
        {m365_copilot}
    )

    # S07 -> S08
    m365_malicious_email.add_associated_assets(
        "ragStore",
        {m365_copilot_rag}
    )

    # S09 -> S10
    # Reuses existing RAGKnowledgeBase <-> LLMConversation
    m365_copilot_rag.add_associated_assets(
        "triggeredConversation",
        {m365_conversation}
    )

    # S10 -> S11
    # Reuses existing LLMConversation <-> AITool
    m365_conversation.add_associated_assets(
        "tool",
        {m365_search_tool}
    )

    # S11 -> S12
    # Reuses existing AITool <-> LLMRenderedResponse
    m365_search_tool.add_associated_assets(
        "renderedResponse",
        {m365_response}
    )

    # S12 -> S13
    # Reuses existing LLMRenderedResponse <-> ExternalHarm
    m365_response.add_associated_assets(
        "externalHarm",
        {m365_financial_impact}
    )
    
    # ========================================================
    # AML.CS0027
    # Organization Confusion on Hugging Face
    # ========================================================

    fake_hf_org = model.add_asset(
        "HFOrganizationAccount",
        "FakeHuggingFaceOrganization"
    )

    hf_private_model = model.add_asset(
        "PoisonableAIModel",
        "HuggingFacePrivateModel"
    )

    hf_ip_theft = model.add_asset(
        "ExternalHarm",
        "HuggingFaceModelIPTheft"
    )

    hf_poisoned_publisher = model.add_asset(
        "PoisonedAIModelPublisher",
        "HFOrgConfusionPublisher"
    )

    hf_model_supply_chain = model.add_asset(
        "AISupplyChainModel",
        "HuggingFaceModelSupplyChain"
    )

    victim_ai_environment = model.add_asset(
        "HuggingFaceVictimOS",
        "VictimAIEnvironment"
    )

    sliver_c2 = model.add_asset(
        "AICyberCommunication",
        "SliverC2Channel"
    )

    sliver_exfiltration = model.add_asset(
        "AIExfiltration",
        "SliverCredentialExfiltration"
    )

    victim_artifact_discovery = model.add_asset(
        "AIArtifactDiscovery",
        "VictimAIArtifactDiscovery"
    )

    easyedit_tool = model.add_asset(
        "AdversarialAttackImplementation",
        "EasyEditTool"
    )

    victim_llama_model = model.add_asset(
        "PoisonableAIModel",
        "VictimLlamaModel"
    )

    manipulated_model_harm = model.add_asset(
        "ExternalHarm",
        "ManipulatedModelExternalHarm"
    )
    
    # --------------------------------------------------------
    # CS0027 associations
    # --------------------------------------------------------

    # S01 -> S02
    fake_hf_org.add_associated_assets(
        "repositoryModel",
        {hf_private_model}
    )

    # S02 -> S03
    # Reuses PoisonableAIModel <-> ExternalHarm
    hf_private_model.add_associated_assets(
        "impact",
        {hf_ip_theft}
    )

    # S03 -> S04
    hf_ip_theft.add_associated_assets(
        "malwareTarget",
        {hf_private_model}
    )

    # S04 -> S05
    # Reuses PoisonableAIModel <-> PoisonedAIModelPublisher
    hf_private_model.add_associated_assets(
        "publisher",
        {hf_poisoned_publisher}
    )

    # S05 -> S06
    hf_poisoned_publisher.add_associated_assets(
        "modelSupplyChain",
        {hf_model_supply_chain}
    )

    # S06 -> S07
    # Reuses AISupplyChainModel <-> PoisonableAIModel
    hf_model_supply_chain.add_associated_assets(
        "integrityTarget",
        {hf_private_model}
    )

    # S07 -> S08
    hf_private_model.add_associated_assets(
        "executionHost",
        {victim_ai_environment}
    )

    # S08 -> S09
    # reverse association also supports S09 -> S10
    victim_ai_environment.add_associated_assets(
        "c2",
        {sliver_c2}
    )

    # S10 -> S11
    victim_ai_environment.add_associated_assets(
        "exfiltration",
        {sliver_exfiltration}
    )

    # S11 -> S12
    sliver_exfiltration.add_associated_assets(
        "artifactDiscovery",
        {victim_artifact_discovery}
    )

    # S12 -> S13
    victim_artifact_discovery.add_associated_assets(
        "attackImplementation",
        {easyedit_tool}
    )

    # S13 -> S14
    easyedit_tool.add_associated_assets(
        "poisonTarget",
        {victim_llama_model}
    )

    # S14 -> S15
    # Reuses PoisonableAIModel <-> ExternalHarm
    victim_llama_model.add_associated_assets(
        "impact",
        {manipulated_model_harm}
    )
    
    # ========================================================
    # AML.CS0028
    # AI Model Tampering via Supply Chain Attack
    # ========================================================

    container_registry_research = model.add_asset(
        "AIResearchMaterial",
        "ContainerRegistryResearch"
    )

    exposed_container_registry = model.add_asset(
        "AIContainerRegistry",
        "ExposedAIContainerRegistry"
    )

    registry_artifact_discovery = model.add_asset(
        "AIArtifactDiscovery",
        "ContainerRegistryArtifactDiscovery"
    )

    exposed_registry_model = model.add_asset(
        "PoisonableAIModel",
        "ExposedRegistryAIModel"
    )

    registry_model_ip_theft = model.add_asset(
        "ExternalHarm",
        "ContainerRegistryModelIPTheft"
    )

    deployed_tampered_model = model.add_asset(
        "PredictiveAIModel",
        "DeployedTamperedAIModel"
    )
    
    # --------------------------------------------------------
    # CS0028 associations
    # --------------------------------------------------------

    # S00 -> S01
    container_registry_research.add_associated_assets(
        "registryTarget",
        {exposed_container_registry}
    )

    # S01 -> S02
    exposed_container_registry.add_associated_assets(
        "artifactDiscovery",
        {registry_artifact_discovery}
    )

    # S02 -> S03
    registry_artifact_discovery.add_associated_assets(
        "discoveredModel",
        {exposed_registry_model}
    )

    # S03 -> S04
    # Reuses PoisonableAIModel <-> ExternalHarm
    exposed_registry_model.add_associated_assets(
        "impact",
        {registry_model_ip_theft}
    )

    # S04 -> S05
    # Reuses ExternalHarm <-> PoisonableAIModel from CS0027
    registry_model_ip_theft.add_associated_assets(
        "malwareTarget",
        {exposed_registry_model}
    )

    # S06 -> S07
    exposed_registry_model.add_associated_assets(
        "registrySupplyChain",
        {exposed_container_registry}
    )

    # S07 -> S08
    exposed_container_registry.add_associated_assets(
        "deploymentTarget",
        {deployed_tampered_model}
    )
    
    # ========================================================
    # AML.CS0029
    # Google Bard Conversation Exfiltration
    # ========================================================

    bard_exfiltration_prompt = model.add_asset(
        "LLMPrompt",
        "BardExfiltrationPrompt"
    )

    bard_infrastructure = model.add_asset(
        "AIInfrastructure",
        "BardGoogleAppsInfrastructure"
    )

    bard_capability = model.add_asset(
        "AdversarialCapability",
        "BardExfiltrationCapability"
    )

    bard_application = model.add_asset(
        "PublicFacingLLMApplication",
        "BardTargetApplication"
    )

    bard_conversation = model.add_asset(
        "LLMConversation",
        "BardConversation"
    )

    bard_rendered_response = model.add_asset(
        "LLMRenderedResponse",
        "BardRenderedExfiltration"
    )

    bard_user_impact = model.add_asset(
        "ExternalHarm",
        "BardUserImpact"
    )
    
    # --------------------------------------------------------
    # CS0029 associations
    # --------------------------------------------------------

    # S00 -> S01
    bard_exfiltration_prompt.add_associated_assets(
        "infrastructure",
        {bard_infrastructure}
    )

    # S01 -> S02
    bard_infrastructure.add_associated_assets(
        "capability",
        {bard_capability}
    )

    # S02 -> S03
    bard_capability.add_associated_assets(
        "publicLLMTarget",
        {bard_application}
    )

    # S03 -> S04
    bard_application.add_associated_assets(
        "indirectConversation",
        {bard_conversation}
    )

    # S04 -> S05
    bard_conversation.add_associated_assets(
        "renderedResponse",
        {bard_rendered_response}
    )

    # S05 -> S06
    # Reuses existing LLMRenderedResponse <-> ExternalHarm
    bard_rendered_response.add_associated_assets(
        "externalHarm",
        {bard_user_impact}
    )
    
    # ========================================================
    # AML.CS0030
    # LLMjacking
    # ========================================================

    llmjacking_victim_host = model.add_asset(
        "LLMJackingVictimOS",
        "LLMJackingVictimHost"
    )

    compromised_cloud_llm = model.add_asset(
        "LLMJackingCloudEnvironment",
        "CompromisedCloudLLMEnvironment"
    )

    llmjacking_keychecker = model.add_asset(
        "LLMJackingSoftwareTool",
        "LLMJackingKeychecker"
    )

    llmjacking_resource_discovery = model.add_asset(
        "EnterpriseResourceDiscovery",
        "LLMJackingResourceDiscovery"
    )

    llmjacking_reverse_proxy = model.add_asset(
        "LLMJackingSoftwareTool",
        "LLMJackingReverseProxy"
    )

    llmjacking_financial_impact = model.add_asset(
        "ExternalHarm",
        "LLMJackingFinancialImpact"
    )
    
    # --------------------------------------------------------
    # CS0030 associations
    # --------------------------------------------------------

    # S01 -> S02
    llmjacking_victim_host.add_associated_assets(
        "cloudEnvironment",
        {compromised_cloud_llm}
    )

    # S02 -> S03
    compromised_cloud_llm.add_associated_assets(
        "keyChecker",
        {llmjacking_keychecker}
    )

    # S03 -> S04
    llmjacking_keychecker.add_associated_assets(
        "resourceDiscovery",
        {llmjacking_resource_discovery}
    )

    # S04 -> S05
    llmjacking_resource_discovery.add_associated_assets(
        "proxyTool",
        {llmjacking_reverse_proxy}
    )

    # S05 -> S06
    llmjacking_reverse_proxy.add_associated_assets(
        "impact",
        {llmjacking_financial_impact}
    )
    
    # ========================================================
    # AML.CS0031
    # Malicious Models on Hugging Face
    # ========================================================

    cs0031_malicious_model = model.add_asset(
        "PoisonableAIModel",
        "CS0031MaliciousHuggingFaceModel"
    )

    cs0031_publisher = model.add_asset(
        "PoisonedAIModelPublisher",
        "CS0031HuggingFacePublisher"
    )

    cs0031_supply_chain = model.add_asset(
        "AISupplyChainModel",
        "CS0031ModelSupplyChain"
    )

    cs0031_reverse_shell = model.add_asset(
        "AICyberCommunication",
        "CS0031ReverseShell"
    )
    
    # --------------------------------------------------------
    # CS0031 associations
    # --------------------------------------------------------

    # S00 -> S01
    cs0031_malicious_model.add_associated_assets(
        "publisher",
        {cs0031_publisher}
    )

    # Also provides the reverse publisher.poisonedModel field,
    # which enables S01 -> S02.

    # S02 -> S03
    # Also provides S03 -> S04 through integrityTarget.
    cs0031_supply_chain.add_associated_assets(
        "integrityTarget",
        {cs0031_malicious_model}
    )

    # S04 -> S05
    cs0031_malicious_model.add_associated_assets(
        "c2",
        {cs0031_reverse_shell}
    )
    
    # ========================================================
    # AML.CS0032
    # Attempted Evasion of ML Phishing Webpage Detection System
    # ========================================================

    modified_phishing_webpage = model.add_asset(
        "AdversarialSample",
        "ModifiedPhishingWebpage"
    )

    phishing_visual_detector = model.add_asset(
        "AIMalwareDetector",
        "PhishingVisualSimilarityModel"
    )

    cs0032_phishing_campaign = model.add_asset(
        "PhishingBrowser",
        "CS0032PhishingCampaign"
    )

    cs0032_user_impact = model.add_asset(
        "ExternalHarm",
        "CS0032UserImpact"
    )
    
    # --------------------------------------------------------
    # CS0032 associations
    # --------------------------------------------------------

    # S00 -> S01
    # Reuses existing AdversarialSample.evasionTarget
    modified_phishing_webpage.add_associated_assets(
        "evasionTarget",
        {phishing_visual_detector}
    )

    # S01 -> S02
    phishing_visual_detector.add_associated_assets(
        "phishingCampaign",
        {cs0032_phishing_campaign}
    )

    # S02 -> S03
    cs0032_phishing_campaign.add_associated_assets(
        "impact",
        {cs0032_user_impact}
    )
    
    # ========================================================
    # AML.CS0033
    # Live Deepfake Image Injection to Evade Mobile KYC
    # Verification
    # ========================================================

    cs0033_victim_identity = model.add_asset(
        "VictimIdentityInformation",
        "CS0033VictimIdentity"
    )

    cs0033_faceswap = model.add_asset(
        "GenerativeAICapability",
        "CS0033Faceswap"
    )

    cs0033_obs = model.add_asset(
        "AIAttackSoftwareTool",
        "CS0033OBS"
    )

    cs0033_virtual_camera = model.add_asset(
        "AIObtainedCapability",
        "CS0033VirtualCamera"
    )

    cs0033_deepfake = model.add_asset(
        "DeepfakeMedia",
        "CS0033LiveDeepfake"
    )

    cs0033_account = model.add_asset(
        "FraudulentAccount",
        "CS0033FraudulentAccount"
    )

    cs0033_kyc_system = model.add_asset(
        "FacialRecognitionSystem",
        "CS0033MobileKYCSystem"
    )

    cs0033_financial_impact = model.add_asset(
        "ExternalHarm",
        "CS0033FinancialImpact"
    )
    
    # --------------------------------------------------------
    # CS0033 associations
    # --------------------------------------------------------

    # S00 -> S01
    # AML.T0087 -> AML.T0016.002
    cs0033_victim_identity.add_associated_assets(
        "generativeAI",
        {cs0033_faceswap}
    )

    # S01 -> S02
    # AML.T0016.002 -> AML.T0016.001
    cs0033_faceswap.add_associated_assets(
        "softwareTool",
        {cs0033_obs}
    )

    # S02 -> S03
    # AML.T0016.001 -> AML.T0016
    cs0033_obs.add_associated_assets(
        "obtainedCapability",
        {cs0033_virtual_camera}
    )

    # S03 -> S04
    # AML.T0016 -> AML.T0088
    cs0033_virtual_camera.add_associated_assets(
        "deepfake",
        {cs0033_deepfake}
    )

    # S04 -> S05
    # AML.T0088 -> AML.T0021
    cs0033_deepfake.add_associated_assets(
        "account",
        {cs0033_account}
    )

    # S05 -> S06
    # AML.T0021 -> AML.T0047
    cs0033_account.add_associated_assets(
        "targetSystem",
        {cs0033_kyc_system}
    )

    # S08 -> S09
    # AML.T0073 -> AML.T0048.000
    cs0033_account.add_associated_assets(
        "impact",
        {cs0033_financial_impact}
    )
    
    # ========================================================
    # AML.CS0034
    # ProKYC: Deepfake Tool for Account Fraud Attacks
    # ========================================================

    cs0034_victim_identity = model.add_asset(
        "VictimIdentityInformation",
        "CS0034VictimIdentity"
    )

    cs0034_prokyc = model.add_asset(
        "GenerativeAICapability",
        "CS0034ProKYCTool"
    )

    cs0034_identity_document = model.add_asset(
        "DeepfakeMedia",
        "CS0034FakeIdentityDocument"
    )

    cs0034_selfie_video = model.add_asset(
        "DeepfakeMedia",
        "CS0034DeepfakeSelfieVideo"
    )

    cs0034_account = model.add_asset(
        "FraudulentAccount",
        "CS0034FraudulentAccount"
    )

    cs0034_kyc_system = model.add_asset(
        "FacialRecognitionSystem",
        "CS0034KYCSystem"
    )

    cs0034_financial_impact = model.add_asset(
        "ExternalHarm",
        "CS0034FinancialImpact"
    )
    
    # --------------------------------------------------------
    # CS0034 associations
    # --------------------------------------------------------

    # S00 -> S01
    # AML.T0087 -> AML.T0016.002
    cs0034_victim_identity.add_associated_assets(
        "generativeAI",
        {cs0034_prokyc}
    )

    # S01 -> S02
    # AML.T0016.002 -> AML.T0088
    cs0034_prokyc.add_associated_assets(
        "deepfake",
        {cs0034_identity_document}
    )

    # S02 -> S03
    # AML.T0088 -> AML.T0088
    cs0034_identity_document.add_associated_assets(
        "relatedDeepfake",
        {cs0034_selfie_video}
    )

    # S03 -> S04
    # AML.T0088 -> AML.T0021
    cs0034_selfie_video.add_associated_assets(
        "account",
        {cs0034_account}
    )

    # S04 -> S05
    # AML.T0021 -> AML.T0047
    cs0034_account.add_associated_assets(
        "targetSystem",
        {cs0034_kyc_system}
    )

    # S07 -> S08
    # AML.T0073 -> AML.T0048.000
    cs0034_account.add_associated_assets(
        "impact",
        {cs0034_financial_impact}
    )
    
    # ========================================================
    # AML.CS0035
    # Data Exfiltration from Slack AI via
    # Indirect Prompt Injection
    # ========================================================

    slack_malicious_message = model.add_asset(
        "LLMPrompt",
        "SlackMaliciousMessage"
    )

    slack_workspace = model.add_asset(
        "AIServiceOS",
        "SlackWorkspace"
    )

    slack_ai = model.add_asset(
        "PublicFacingLLMApplication",
        "SlackAI"
    )

    slack_rag = model.add_asset(
        "RAGKnowledgeBase",
        "SlackAIRAG"
    )

    slack_conversation = model.add_asset(
        "LLMConversation",
        "SlackAIConversation"
    )

    slack_rendered_response = model.add_asset(
        "LLMRenderedResponse",
        "SlackRenderedExfiltration"
    )
    
    # --------------------------------------------------------
    # CS0035 associations
    # --------------------------------------------------------

    # S01 -> S02
    # AML.T0065 -> AML.T0012
    slack_malicious_message.add_associated_assets(
        "serviceOS",
        {slack_workspace}
    )

    # S02 -> S03
    # AML.T0012 -> AML.T0047
    slack_workspace.add_associated_assets(
        "publicLLMApp",
        {slack_ai}
    )

    # S03 -> S04
    # AML.T0047 -> AML.T0070
    # Reuses existing PublicFacingLLMApplication
    # <-> RAGKnowledgeBase association
    slack_ai.add_associated_assets(
        "ragStore",
        {slack_rag}
    )

    # S04 -> S05
    # AML.T0070 -> AML.T0051.001
    #
    # Reverse association also provides:
    # SlackAIConversation.credentialRAG -> SlackAIRAG
    slack_rag.add_associated_assets(
        "indirectConversation",
        {slack_conversation}
    )

    # S06 -> S07
    # AML.T0082 -> AML.T0077
    slack_rag.add_associated_assets(
        "renderedResponse",
        {slack_rendered_response}
    )
    
    # ========================================================
    # AML.CS0036
    # AIKatz: Attacking LLM Desktop Applications
    # ========================================================

    aikatz_client_os = model.add_asset(
        "AIClientOS",
        "AIKatzVictimDesktop"
    )

    aikatz_backend = model.add_asset(
        "AIBackendService",
        "AIKatzLLMBackend"
    )

    aikatz_llm_application = model.add_asset(
        "PublicFacingLLMApplication",
        "AIKatzLLMApplication"
    )

    aikatz_context = model.add_asset(
        "AIAgentContext",
        "AIKatzAgentContext"
    )

    aikatz_conversation = model.add_asset(
        "LLMConversation",
        "AIKatzConversation"
    )

    aikatz_external_impact = model.add_asset(
        "ExternalHarm",
        "AIKatzExternalImpact"
    )

    aikatz_service_impact = model.add_asset(
        "AIServiceImpact",
        "AIKatzServiceImpact"
    )
    
    # --------------------------------------------------------
    # CS0036 associations
    # --------------------------------------------------------
    
        # S02/S03 -> S04
    aikatz_client_os.add_associated_assets(
        "backendService",
        {aikatz_backend}
    )

    # S04 -> S05
    aikatz_backend.add_associated_assets(
        "aiApplication",
        {aikatz_llm_application}
    )

    # S06 -> S07
    aikatz_llm_application.add_associated_assets(
        "agentContext",
        {aikatz_context}
    )

    # S08 -> S09
    # Uses existing LLMConversation <-> AIAgentContext association
    aikatz_context.add_associated_assets(
        "conversation",
        {aikatz_conversation}
    )

    # Impact branches
    aikatz_conversation.add_associated_assets(
        "externalHarm",
        {aikatz_external_impact}
    )

    aikatz_conversation.add_associated_assets(
        "serviceImpact",
        {aikatz_service_impact}
    )
    
    # ========================================================
    # AML.CS0037
    # Data Exfiltration via Agent Tools in Copilot Studio
    # ========================================================

    cs0037_agent_recon = model.add_asset(
        "AIResearchMaterial",
        "CS0037AgentRecon"
    )

    cs0037_probe_prompt = model.add_asset(
        "LLMPrompt",
        "CS0037ProbePrompt"
    )

    cs0037_copilot_agent = model.add_asset(
        "PublicFacingLLMApplication",
        "CS0037CopilotAgent"
    )

    cs0037_triggered_conversation = model.add_asset(
        "LLMConversation",
        "CS0037TriggeredConversation"
    )

    cs0037_trigger_configuration = model.add_asset(
        "AIAgentConfiguration",
        "CS0037TriggerConfiguration"
    )

    cs0037_discovery_conversation = model.add_asset(
        "LLMConversation",
        "CS0037DiscoveryConversation"
    )

    cs0037_data_configuration = model.add_asset(
        "AIAgentConfiguration",
        "CS0037DataConfiguration"
    )

    cs0037_exfiltration_prompt = model.add_asset(
        "LLMPrompt",
        "CS0037ExfiltrationPrompt"
    )

    cs0037_rag = model.add_asset(
        "RAGKnowledgeBase",
        "CS0037CustomerSupportRAG"
    )

    cs0037_salesforce_tool = model.add_asset(
        "AITool",
        "CS0037SalesforceTool"
    )

    cs0037_email_tool = model.add_asset(
        "AITool",
        "CS0037EmailTool"
    )
    
    # --------------------------------------------------------
    # CS0037 associations
    # --------------------------------------------------------

    # S00 -> S01
    # AML.T0006.003 -> AML.T0065
    cs0037_agent_recon.add_associated_assets(
        "craftedPrompt",
        {cs0037_probe_prompt}
    )

    # S01 -> S02
    # AML.T0065 -> AML.T0093
    cs0037_probe_prompt.add_associated_assets(
        "targetApplication",
        {cs0037_copilot_agent}
    )

    # S02 -> S03
    # AML.T0093 -> AML.T0051.002
    cs0037_copilot_agent.add_associated_assets(
        "triggeredConversation",
        {cs0037_triggered_conversation}
    )

    # S03 -> S04
    # AML.T0051.002 -> AML.T0084.002
    cs0037_triggered_conversation.add_associated_assets(
        "agentConfig",
        {cs0037_trigger_configuration}
    )

    # S05 -> S06
    # AML.T0084.001 -> AML.T0047
    cs0037_trigger_configuration.add_associated_assets(
        "targetApplication",
        {cs0037_copilot_agent}
    )

    # S06 -> S07
    # AML.T0047 -> AML.T0051
    cs0037_copilot_agent.add_associated_assets(
        "conversation",
        {cs0037_discovery_conversation}
    )

    # S07 -> S08
    # AML.T0051 -> AML.T0084.000
    cs0037_discovery_conversation.add_associated_assets(
        "agentConfig",
        {cs0037_data_configuration}
    )

    # S09 -> S10
    # AML.T0084.001 -> AML.T0065
    cs0037_data_configuration.add_associated_assets(
        "craftedPrompt",
        {cs0037_exfiltration_prompt}
    )

    # S10 -> S11
    # AML.T0065 -> AML.T0085.000
    cs0037_exfiltration_prompt.add_associated_assets(
        "ragData",
        {cs0037_rag}
    )

    # S11 -> S12
    # AML.T0085.000 -> AML.T0085.001
    cs0037_rag.add_associated_assets(
        "agentTool",
        {cs0037_salesforce_tool}
    )

    # S12 -> S13
    # AML.T0085.001 -> AML.T0086
    cs0037_salesforce_tool.add_associated_assets(
        "exfiltrationTool",
        {cs0037_email_tool}
    )
    
    # ========================================================
    # AML.CS0038
    # Planting Instructions for Delayed Automatic
    # AI Agent Tool Invocation
    # ========================================================

    cs0038_delayed_prompt = model.add_asset(
        "LLMPrompt",
        "CS0038DelayedPrompt"
    )

    cs0038_gemini = model.add_asset(
        "PublicFacingLLMApplication",
        "CS0038Gemini"
    )

    cs0038_conversation = model.add_asset(
        "LLMConversation",
        "CS0038GeminiConversation"
    )

    cs0038_workspace_extension = model.add_asset(
        "AITool",
        "CS0038WorkspaceExtension"
    )
    
    # --------------------------------------------------------
    # CS0038 associations
    # --------------------------------------------------------

    # S00 -> S01
    # AML.T0065 -> AML.T0093
    cs0038_delayed_prompt.add_associated_assets(
        "targetApplication",
        {cs0038_gemini}
    )

    # S01 -> S02
    # AML.T0093 -> AML.T0051.001
    cs0038_gemini.add_associated_assets(
        "indirectConversation",
        {cs0038_conversation}
    )

    # S03 -> S04
    # AML.T0094 -> AML.T0053
    cs0038_conversation.add_associated_assets(
        "tool",
        {cs0038_workspace_extension}
    )
    
    # ========================================================
    # AML.CS0039
    # Living Off AI: Prompt Injection via
    # Jira Service Management
    # ========================================================

    cs0039_recon = model.add_asset(
        "AIResearchMaterial",
        "CS0039Recon"
    )

    cs0039_malicious_prompt = model.add_asset(
        "LLMPrompt",
        "CS0039MaliciousPrompt"
    )

    cs0039_jsm_application = model.add_asset(
        "PublicFacingLLMApplication",
        "CS0039JSMApplication"
    )

    cs0039_conversation = model.add_asset(
        "LLMConversation",
        "CS0039Conversation"
    )
    cs0039_atlassian_data_tool = model.add_asset(
        "AITool",
        "CS0039AtlassianDataTool"
    )

    cs0039_atlassian_exfiltration_tool = model.add_asset(
        "AITool",
        "CS0039AtlassianExfiltrationTool"
    )
    
    # --------------------------------------------------------
    # CS0039 associations
    # --------------------------------------------------------

    # S01 -> S02
    # AML.T0095 -> AML.T0065
    cs0039_recon.add_associated_assets(
        "craftedPrompt",
        {cs0039_malicious_prompt}
    )

    # S02 -> S03
    # AML.T0065 -> AML.T0093
    cs0039_malicious_prompt.add_associated_assets(
        "targetApplication",
        {cs0039_jsm_application}
    )

    # S03 -> S04
    # AML.T0093 -> AML.T0051.001
    cs0039_jsm_application.add_associated_assets(
        "indirectConversation",
        {cs0039_conversation}
    )

    # S04 -> S05
    # AML.T0051.001 -> AML.T0053
    cs0039_conversation.add_associated_assets(
        "tool",
        {cs0039_atlassian_data_tool}
    )

    # S06 -> S07
    # AML.T0085.001 -> AML.T0086
    cs0039_atlassian_data_tool.add_associated_assets(
        "exfiltrationTool",
        {cs0039_atlassian_exfiltration_tool}
    )
    
    # ========================================================
    # AML.CS0040
    # Hacking ChatGPT's Memories with Prompt Injection
    # ========================================================

    cs0040_memory_poisoning_prompt = model.add_asset(
        "LLMPrompt",
        "CS0040MemoryPoisoningPrompt"
    )

    cs0040_initial_prompt_infiltration = model.add_asset(
        "PublicFacingLLMApplication",
        "CS0040InitialPromptInfiltration"
    )

    cs0040_conversation = model.add_asset(
        "LLMConversation",
        "CS0040Conversation"
    )

    cs0040_memory_context = model.add_asset(
        "AIAgentContext",
        "CS0040MemoryContext"
    )

    cs0040_persistent_prompt_infiltration = model.add_asset(
        "PublicFacingLLMApplication",
        "CS0040PersistentPromptInfiltration"
    )

    cs0040_user_impact = model.add_asset(
        "ExternalHarm",
        "CS0040UserImpact"
    )
    
    # --------------------------------------------------------
    # CS0040 associations
    # --------------------------------------------------------

    # S01 -> S02
    # AML.T0068 -> AML.T0093
    cs0040_memory_poisoning_prompt.add_associated_assets(
        "targetApplication",
        {cs0040_initial_prompt_infiltration}
    )

    # S02 -> S03
    # AML.T0093 -> AML.T0051.001
    cs0040_initial_prompt_infiltration.add_associated_assets(
        "indirectConversation",
        {cs0040_conversation}
    )

    # S03 -> S04
    # AML.T0051.001 -> AML.T0080.000
    cs0040_conversation.add_associated_assets(
        "agentContext",
        {cs0040_memory_context}
    )

    # S04 -> S05
    # AML.T0080.000 -> AML.T0093
    cs0040_memory_context.add_associated_assets(
        "persistentApplication",
        {cs0040_persistent_prompt_infiltration}
    )

    # S05 -> S06
    # AML.T0093 -> AML.T0048.003
    cs0040_persistent_prompt_infiltration.add_associated_assets(
        "externalHarm",
        {cs0040_user_impact}
    )
    
    # ========================================================
    # AML.CS0041
    # Rules File Backdoor: Supply Chain Attack on
    # AI Coding Assistants
    # ========================================================

    cs0041_staged_capability = model.add_asset(
        "LLMStagedCapability",
        "CS0041StagedCapability"
    )

    cs0041_rules_prompt = model.add_asset(
        "LLMPrompt",
        "CS0041RulesPrompt"
    )

    cs0041_poisoned_rules_software = model.add_asset(
        "AISupplyChainSoftware",
        "CS0041PoisonedRulesSoftware"
    )

    cs0041_agent_configuration = model.add_asset(
        "AIAgentConfiguration",
        "CS0041AgentConfiguration"
    )

    cs0041_rules_propagation = model.add_asset(
        "LLMPromptPropagation",
        "CS0041RulesPropagation"
    )

    cs0041_coding_assistant = model.add_asset(
        "AIAgent",
        "CS0041CodingAssistant"
    )

    cs0041_coding_conversation = model.add_asset(
        "LLMConversation",
        "CS0041CodingConversation"
    )

    cs0041_trusted_output = model.add_asset(
        "LLMRenderedResponse",
        "CS0041TrustedOutput"
    )

    cs0041_user_impact = model.add_asset(
        "ExternalHarm",
        "CS0041UserImpact"
    )
    
    # --------------------------------------------------------
    # CS0041 associations
    # --------------------------------------------------------

    # S00 -> S01
    # AML.T0079 -> AML.T0065
    cs0041_staged_capability.add_associated_assets(
        "craftedPrompt",
        {cs0041_rules_prompt}
    )

    # S02 -> S03
    # AML.T0068 -> AML.T0010.001
    cs0041_rules_prompt.add_associated_assets(
        "compromisedSoftware",
        {cs0041_poisoned_rules_software}
    )

    # S03 -> S04
    # AML.T0010.001 -> AML.T0081
    cs0041_poisoned_rules_software.add_associated_assets(
        "agentConfiguration",
        {cs0041_agent_configuration}
    )

    # S04 -> S05
    # AML.T0081 -> AML.T0143
    cs0041_agent_configuration.add_associated_assets(
        "propagation",
        {cs0041_rules_propagation}
    )

    # S05 -> S06
    # AML.T0143 -> AML.T0051.000
    cs0041_rules_propagation.add_associated_assets(
        "targetAgent",
        {cs0041_coding_assistant}
    )

    # S06 -> S07
    # AML.T0051.000 -> AML.T0054
    cs0041_coding_assistant.add_associated_assets(
        "conversation",
        {cs0041_coding_conversation}
    )

    # S07 -> S08
    # AML.T0054 -> AML.T0067
    cs0041_coding_conversation.add_associated_assets(
        "renderedResponse",
        {cs0041_trusted_output}
    )

    # S08 -> S09
    # AML.T0067 -> AML.T0048.003
    cs0041_trusted_output.add_associated_assets(
        "externalHarm",
        {cs0041_user_impact}
    )


    return model


# ============================================================
# DETERMINISTIC CASE-STUDY ATTACKER
# ============================================================

class CaseStudyAttacker(DecisionAgent):

    def __init__(self, agent_config, **_):

        self.attack_path = agent_config.get(
            "attack_path",
            []
        )

        self.case_id = agent_config.get(
            "case_id",
            "UNKNOWN"
        )


    def get_next_action(
        self,
        agent_state,
        **kwargs
    ):

        action_surface = {
            node.full_name: node
            for node in agent_state.action_surface
        }

        performed = {
            node.full_name
            for node in agent_state.performed_nodes
        }


        # ----------------------------------------------------
        # Find next required case-study step
        # ----------------------------------------------------

        remaining_steps = [
            step
            for step in self.attack_path
            if step not in performed
        ]


        # ----------------------------------------------------
        # Case study finished
        # ----------------------------------------------------

        if not remaining_steps:

            print(
                f"[{self.case_id}] "
                "All case-study steps performed."
            )

            return None


        next_step = remaining_steps[0]


        # ----------------------------------------------------
        # Perform next expected action
        # ----------------------------------------------------

        if next_step in action_surface:

            print(
                f"[{self.case_id}] "
                f"[ACTION] {next_step}"
            )

            return action_surface[next_step]


        # ----------------------------------------------------
        # Path stalled
        # ----------------------------------------------------

        print("\n" + "=" * 70)

        print(
            f"[{self.case_id}] "
            "ATTACK PATH STALLED"
        )

        print("=" * 70)

        print(
            "\nNext expected step:"
        )

        print(
            f"  {next_step}"
        )


        print("\nPerformed nodes:")

        for node in sorted(performed):

            print(
                f"  {node}"
            )


        print("\nCurrent action surface:")

        for node in sorted(action_surface):

            print(
                f"  {node}"
            )


        print("=" * 70)


        raise RuntimeError(
            f"{self.case_id} stalled at: "
            f"{next_step}"
        )


# ============================================================
# VERIFY CASE STUDY NODES
# ============================================================

def verify_case(
    attack_graph,
    case_id,
    case_config
):

    print("\n" + "=" * 70)

    print(
        f"CHECKING {case_id} ATTACK STEPS"
    )

    print("=" * 70)


    expected_nodes = [

        case_config["entry_point"],

        *case_config["path"]
    ]


    all_found = True


    for node_name in expected_nodes:

        try:

            attack_graph.get_node_by_full_name(
                node_name
            )

            print(
                f"[OK]      {node_name}"
            )


        except Exception:

            print(
                f"[MISSING] {node_name}"
            )

            all_found = False


    return all_found


# ============================================================
# CREATE ATTACKER SETTINGS
# ============================================================

def create_attacker(
    case_id,
    case_config
):

    return AttackerSettings(

        name=case_config[
            "attacker_name"
        ],

        entry_points={
            case_config[
                "entry_point"
            ]
        },

        goals={
            case_config[
                "goal"
            ]
        },

        policy=CaseStudyAttacker,

        config={

            "case_id":
                case_id,

            "attack_path":
                case_config["path"],
        }
    )


# ============================================================
# PRINT RESULT
# ============================================================

def print_result(
    actions,
    case_id,
    case_config
):

    attacker_name = (
        case_config[
            "attacker_name"
        ]
    )

    entry_point = (
        case_config[
            "entry_point"
        ]
    )

    goal = (
        case_config[
            "goal"
        ]
    )


    attacker_actions = actions.get(
        attacker_name,
        []
    )


    print("\n" + "=" * 70)

    print(
        f"{case_id} SIMULATION RESULT"
    )

    print("=" * 70)


    print(
        "\nENTRY POINT:"
    )

    print(
        f"  {entry_point}"
    )


    print(
        "\nATTACK PATH:"
    )


    for i, node in enumerate(
        attacker_actions,
        start=1
    ):

        if node is not None:

            print(
                f"  {i:02d}. "
                f"{node.full_name}"
            )


    # --------------------------------------------------------
    # Check goal
    # --------------------------------------------------------

    goal_reached = any(

        node is not None
        and node.full_name == goal

        for node in attacker_actions
    )


    print(
        "\nGOAL:"
    )

    print(
        f"  {goal}"
    )

    print()


    if goal_reached:

        print(
            f"[SUCCESS] "
            f"{case_id} goal reached."
        )

    else:

        print(
            f"[FAILED] "
            f"{case_id} goal was not reached."
        )


    print("=" * 70)


    return goal_reached


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # 1. LOAD LANGUAGE
    # ========================================================

    print(
        "Loading MAL language..."
    )

    lang_graph = (
        LanguageGraph.load_from_file(
            str(LANG_FILE)
        )
    )

    print(
        "Language loaded successfully."
    )


    # ========================================================
    # 2. CREATE SYSTEM MODEL
    # ========================================================

    print(
        "\nCreating model..."
    )

    model = create_model(
        lang_graph
    )

    print(
        "Model created successfully."
    )


    # ========================================================
    # 3. CREATE ATTACK GRAPH
    # ========================================================

    print(
        "\nGenerating attack graph..."
    )

    attack_graph = AttackGraph(
        lang_graph,
        model
    )

    print(
        "Attack graph generated successfully."
    )


    # ========================================================
    # 4. VERIFY ALL CASE STUDIES
    # ========================================================

    validation_results = {}


    for case_id, config in (
        CASE_STUDIES.items()
    ):

        validation_results[
            case_id
        ] = verify_case(
            attack_graph,
            case_id,
            config
        )


    # --------------------------------------------------------
    # Stop if any case has missing nodes
    # --------------------------------------------------------

    invalid_cases = [

        case_id

        for case_id, valid
        in validation_results.items()

        if not valid
    ]


    if invalid_cases:

        raise RuntimeError(

            "Missing attack-graph nodes for: "
            + ", ".join(invalid_cases)
        )


    # ========================================================
    # 5. CREATE ATTACKERS
    # ========================================================

    attackers = [

        create_attacker(
            case_id,
            config
        )

        for case_id, config
        in CASE_STUDIES.items()
    ]


    # ========================================================
    # 6. CREATE SIMULATOR
    # ========================================================

    simulator = MalSimulator(

        attack_graph,

        agents=attackers
    )


    # ========================================================
    # 7. RUN SIMULATION
    # ========================================================

    print("\n" + "=" * 70)

    print(
        "RUNNING MITRE ATLAS "
        "CASE-STUDY SIMULATIONS"
    )

    print("=" * 70)


    actions = run_simulation(
        simulator
    )


    # ========================================================
    # 8. PRINT RESULTS
    # ========================================================

    results = {}


    for case_id, config in (
        CASE_STUDIES.items()
    ):

        results[
            case_id
        ] = print_result(
            actions,
            case_id,
            config
        )


    # ========================================================
    # 9. OVERALL RESULT
    # ========================================================

    print("\n" + "=" * 70)

    print(
        "OVERALL SIMULATION RESULT"
    )

    print("=" * 70)


    for case_id, success in (
        results.items()
    ):

        status = (
            "SUCCESS"
            if success
            else "FAILED"
        )

        print(
            f"{case_id}: {status}"
        )


    print("=" * 70)


    # ========================================================
    # 10. COMPLETE RECORDING
    # ========================================================

    print(
        "\nComplete simulator recording:\n"
    )

    pprint.pprint(
        simulator.recording
    )


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":
    main()
