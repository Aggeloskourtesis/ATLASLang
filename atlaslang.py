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
