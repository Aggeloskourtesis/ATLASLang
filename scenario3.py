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
# DEFENSE CONTROL
# ============================================================
#
# Defenses are NOT enabled/disabled from this Python file.
# Their state is defined directly in atlaslang.mal /
# enterpriselang.mal using [Disabled] or [Enabled].
#
# The same Python scenario is therefore used for both the
# baseline and defended experiments.
#



# Choose:
#
#   "develop" -> T1587.001 Develop Malware
#   "obtain"  -> T1588.001 Obtain Malware
#
MALWARE_ROUTE = "develop"


# ============================================================
# ENTRY POINT
# ============================================================

ENTRY_POINT = (
    "FabricatedGuidelinePrompt:"
    "llmPromptCrafting"
)


# ============================================================
# RESOURCE DEVELOPMENT BRANCH
# ============================================================

if MALWARE_ROUTE == "develop":

    MALWARE_STEP = (
        "MaliciousExtensionPreparation:"
        "developMalware"
    )

elif MALWARE_ROUTE == "obtain":

    MALWARE_STEP = (
        "MaliciousExtensionPreparation:"
        "obtainMalware"
    )

else:

    raise ValueError(
        "MALWARE_ROUTE must be "
        "'develop' or 'obtain'"
    )


# ============================================================
# ATTACK PATH
# ============================================================

ATTACK_PATH = [

    # --------------------------------------------------------
    # ATT&CK - Resource Development
    # --------------------------------------------------------

    # T1587.001 or T1588.001
    MALWARE_STEP,


    # --------------------------------------------------------
    # Internal enterpriseLang precursor
    # --------------------------------------------------------

    "VictimBrowser:installExtensions",


    # --------------------------------------------------------
    # ATT&CK - Persistence
    # --------------------------------------------------------

    # T1176.001
    "VictimBrowser:browserExtensions",


    # --------------------------------------------------------
    # ATT&CK - Collection
    # --------------------------------------------------------

    # T1056
    "VictimEndpointOS:inputCapture",


    # internal enterpriseLang step
    "VictimEndpointOS:"
    "attemptAutomatedCollection",


    # T1119
    "VictimEndpointOS:"
    "automatedCollection",


    # --------------------------------------------------------
    # Internal enterpriseLang precursor
    # --------------------------------------------------------

    "LLMCommunicationNetwork:"
    "attemptTransmittedDataManipulation",


    # --------------------------------------------------------
    # ATT&CK - Impact
    # --------------------------------------------------------

    # T1565.002
    "LLMCommunicationNetwork:"
    "transmittedDataManipulation",


    # --------------------------------------------------------
    # ATLAS - Execution
    # --------------------------------------------------------

    # AML.T0051
    "TargetLLMConversation:"
    "llmPromptInjection",


    # --------------------------------------------------------
    # ATLAS - Persistence
    # --------------------------------------------------------

    # AML.T0080.001
    "PoisonedConversationContext:"
    "contextPoisoningThread",


    # --------------------------------------------------------
    # ATLAS - Impact
    # --------------------------------------------------------

    # AML.T0048.003
    "PatientSafetyImpact:userHarm",
]


# Internal MAL steps that should not be shown as
# techniques in the final mapped path.
AUXILIARY_STEPS = {

    "VictimBrowser:installExtensions",

    "VictimEndpointOS:"
    "attemptAutomatedCollection",

    "LLMCommunicationNetwork:"
    "attemptTransmittedDataManipulation",
}


# ============================================================
# CREATE MODEL
# ============================================================

def create_model(
    lang_graph: LanguageGraph
) -> Model:

    model = Model(
        "LLM_BROWSER_EXTENSION_SCENARIO",
        lang_graph
    )


    # ========================================================
    # ATLAS
    # AML.T0065 - LLM Prompt Crafting
    # ========================================================

    fabricated_prompt = model.add_asset(
        "LLMPrompt",
        "FabricatedGuidelinePrompt"
    )


    # ========================================================
    # ATT&CK
    # T1587.001 / T1588.001
    # ========================================================

    extension_preparation = model.add_asset(
        "AttackPreparation",
        "MaliciousExtensionPreparation"
    )


    # ========================================================
    # ATT&CK
    # T1176.001
    # ========================================================

    victim_browser = model.add_asset(
        "PromptInterceptBrowser",
        "VictimBrowser"
    )


    # ========================================================
    # ATT&CK
    # T1056 + T1119
    # ========================================================

    victim_os = model.add_asset(
        "PromptCaptureOS",
        "VictimEndpointOS"
    )


    victim_computer = model.add_asset(
        "Computer",
        "VictimWorkstation"
    )


    # ========================================================
    # Network
    # ========================================================

    router = model.add_asset(
        "Router",
        "VictimRouter"
    )


    prompt_network = model.add_asset(
        "PromptManipulationNetwork",
        "LLMCommunicationNetwork"
    )


    # ========================================================
    # ATLAS
    # AML.T0051
    # ========================================================

    llm_conversation = model.add_asset(
        "LLMConversation",
        "TargetLLMConversation"
    )


    # ========================================================
    # ATLAS
    # AML.T0080.001
    # ========================================================

    poisoned_context = model.add_asset(
        "AIAgentContext",
        "PoisonedConversationContext"
    )


    # ========================================================
    # ATLAS
    # AML.T0048.003
    # ========================================================

    patient_harm = model.add_asset(
        "ExternalHarm",
        "PatientSafetyImpact"
    )


    # ========================================================
    # ASSOCIATIONS
    # ========================================================


    # --------------------------------------------------------
    # AML.T0065
    #      ->
    # T1587.001 / T1588.001
    # --------------------------------------------------------

    fabricated_prompt.add_associated_assets(
        "browserPreparation",
        {extension_preparation}
    )


    # --------------------------------------------------------
    # Malware preparation -> browser
    # --------------------------------------------------------

    extension_preparation.add_associated_assets(
        "browser",
        {victim_browser}
    )


    # --------------------------------------------------------
    # Browser -> endpoint OS
    # --------------------------------------------------------

    victim_browser.add_associated_assets(
        "captureOS",
        {victim_os}
    )


    # --------------------------------------------------------
    # Computer -> OS
    # --------------------------------------------------------

    victim_computer.add_associated_assets(
        "os",
        {victim_os}
    )


    # --------------------------------------------------------
    # Computer -> router
    # --------------------------------------------------------

    victim_computer.add_associated_assets(
        "router",
        {router}
    )


    # --------------------------------------------------------
    # Router -> internal network
    # --------------------------------------------------------

    router.add_associated_assets(
        "internalNetwork",
        {prompt_network}
    )


    # --------------------------------------------------------
    # T1565.002
    #      ->
    # AML.T0051
    # --------------------------------------------------------

    prompt_network.add_associated_assets(
        "llmConversation",
        {llm_conversation}
    )


    # --------------------------------------------------------
    # AML.T0051
    #      ->
    # AML.T0080.001
    # --------------------------------------------------------

    llm_conversation.add_associated_assets(
        "agentContext",
        {poisoned_context}
    )


    # --------------------------------------------------------
    # AML.T0080.001
    #      ->
    # AML.T0048.003
    # --------------------------------------------------------

    poisoned_context.add_associated_assets(
        "externalHarm",
        {patient_harm}
    )


    return model


# ============================================================
# DETERMINISTIC ATTACKER
# ============================================================

class LLMExtensionAttacker(DecisionAgent):

    def __init__(
        self,
        agent_config,
        **_
    ):

        self.attack_path = agent_config.get(
            "attack_path",
            ATTACK_PATH
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


        remaining = [

            step

            for step in self.attack_path

            if step not in performed
        ]


        if not remaining:

            print(
                "[INFO] LLM browser-extension "
                "attack completed."
            )

            return None


        next_step = remaining[0]


        if next_step in action_surface:

            if next_step in AUXILIARY_STEPS:

                print(
                    f"[INTERNAL] {next_step}"
                )

            else:

                print(
                    f"[ACTION]   {next_step}"
                )


            return action_surface[
                next_step
            ]


        # ----------------------------------------------------
        # DEBUG
        # ----------------------------------------------------

        print("\n" + "=" * 70)

        print(
            "[STALLED] LLM browser-extension attack"
        )

        print("=" * 70)


        print(
            f"\nNext expected step:\n"
            f"  {next_step}"
        )


        print("\nPerformed:")

        for node in sorted(performed):

            print(
                f"  {node}"
            )


        print(
            "\nCurrent action surface:"
        )

        for node in sorted(
            action_surface
        ):

            print(
                f"  {node}"
            )


        print("=" * 70)


        print(
            "\n[ATTACK BLOCKED / PATH UNREACHABLE]"
        )

        print(
            "The expected next attack step is not "
            "available to the attacker."
        )

        print(
            "If a defense is [Enabled] in atlaslang.mal "
            "or enterpriselang.mal, this is the expected "
            "defensive outcome."
        )

        return None


# ============================================================
# VERIFY NODES
# ============================================================

def verify_nodes(
    attack_graph: AttackGraph
):

    print("\n" + "=" * 70)

    print(
        "VERIFYING LLM BROWSER-EXTENSION SCENARIO"
    )

    print("=" * 70)


    expected_nodes = [
        ENTRY_POINT,
        *ATTACK_PATH,
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
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # 1. Load language
    # --------------------------------------------------------

    print(
        "Loading atlaslang.mal..."
    )

    lang_graph = (
        LanguageGraph.load_from_file(
            str(LANG_FILE)
        )
    )

    print(
        "Language loaded successfully."
    )


    # --------------------------------------------------------
    # 2. Create model
    # --------------------------------------------------------

    print(
        "\nCreating LLM browser-extension model..."
    )

    model = create_model(
        lang_graph
    )

    print(
        "Model created successfully."
    )


    # --------------------------------------------------------
    # 3. Generate attack graph
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # 4. Verify nodes
    # --------------------------------------------------------

    if not verify_nodes(
        attack_graph
    ):

        raise RuntimeError(
            "One or more expected attack "
            "nodes are missing."
        )


    # --------------------------------------------------------
    # 5. Attacker
    # --------------------------------------------------------

    attacker = AttackerSettings(

        name="LLM_Extension_Attacker",

        entry_points={
            ENTRY_POINT
        },

        goals={
            "PatientSafetyImpact:userHarm"
        },

        policy=LLMExtensionAttacker,

        config={
            "attack_path":
                ATTACK_PATH
        }
    )


    # --------------------------------------------------------
    # 6. Simulator
    # --------------------------------------------------------

    simulator = MalSimulator(

        attack_graph,

        agents=[
            attacker
        ]
    )


    # --------------------------------------------------------
    # 7. Run
    # --------------------------------------------------------

    print("\n" + "=" * 70)

    print(
        "RUNNING LLM BROWSER-EXTENSION SCENARIO"
    )

    print(
        "Defense configuration is read directly from "
        "atlaslang.mal / enterpriselang.mal."
    )

    print(
        f"MALWARE ROUTE: {MALWARE_ROUTE.upper()}"
    )

    print("=" * 70)


    actions = run_simulation(
        simulator
    )


    # --------------------------------------------------------
    # 8. Results
    # --------------------------------------------------------

    attacker_actions = actions.get(
        "LLM_Extension_Attacker",
        []
    )


    print("\n" + "=" * 70)

    print(
        "LLM BROWSER-EXTENSION SCENARIO RESULT"
    )

    print("=" * 70)


    print(
        f"\nENTRY POINT:\n"
        f"  {ENTRY_POINT}"
    )


    print(
        "\nMAPPED ATTACK PATH:"
    )


    mapped_index = 1


    for node in attacker_actions:

        if node is None:
            continue

        if (
            node.full_name
            in AUXILIARY_STEPS
        ):
            continue


        print(
            f"  {mapped_index:02d}. "
            f"{node.full_name}"
        )

        mapped_index += 1


    # --------------------------------------------------------
    # Goal
    # --------------------------------------------------------

    performed = {

        node.full_name

        for node in attacker_actions

        if node is not None
    }


    goal = (
        "PatientSafetyImpact:userHarm"
    )


    print(
        "\nFINAL IMPACT:"
    )


    if goal in performed:

        print(
            "  AML.T0048.003 User Harm: "
            "REACHED"
        )

    else:

        print(
            "  AML.T0048.003 User Harm: "
            "NOT REACHED"
        )


    print("\n" + "=" * 70)


    if goal in performed:

        print(
            "[ATTACK SUCCESS] LLM browser-extension "
            "scenario completed."
        )

        print(
            "The configured MAL defenses did not prevent "
            "the complete historical attack path."
        )

    else:

        print(
            "[ATTACK BLOCKED] Final impact "
            "was not reached."
        )

        print(
            "If one or more defenses are [Enabled] in the MAL "
            "language, this indicates that the defended model "
            "prevented the complete historical path."
        )


    print("=" * 70)


    # --------------------------------------------------------
    # Full recording
    # --------------------------------------------------------

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
