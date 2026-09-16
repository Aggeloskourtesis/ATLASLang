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
