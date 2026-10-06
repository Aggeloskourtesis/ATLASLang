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



# ============================================================
# BGMS / URET SCENARIO
# ============================================================

ENTRY_POINT = (
    "URETImplementation:"
    "obtainAdversarialAIAttackImplementation"
)


ATTACK_PATH = [

    # --------------------------------------------------------
    # ATT&CK - Resource Development
    # --------------------------------------------------------

    # T1588.006
    "BGMSAttackPreparation:obtainVulnerabilities",


    # --------------------------------------------------------
    # ATT&CK Mobile - Initial Access
    # --------------------------------------------------------

    # T1664
    "BGMSSmartphone:exploitationForInitialAccess",


    # --------------------------------------------------------
    # ATT&CK - Collection
    # --------------------------------------------------------

    # T1557
    "BGMSSmartphoneOS:manInTheMiddle",


    # --------------------------------------------------------
    # ATLAS - Collection
    # --------------------------------------------------------

    # AML.T0035
    "CGMArtifact:aiArtifactCollection",


    # --------------------------------------------------------
    # ATLAS - AI Attack Staging
    # --------------------------------------------------------

    # AML.T0043
    "AdversarialCGMReading:craftAdversarialData",


    # --------------------------------------------------------
    # Internal enterpriseLang prerequisite
    # --------------------------------------------------------

    "BGMSBluetoothChannel:"
    "attemptTransmittedDataManipulation",


    # --------------------------------------------------------
    # ATT&CK - Impact
    # --------------------------------------------------------

    # T1565.002
    "BGMSBluetoothChannel:"
    "transmittedDataManipulation",


    # --------------------------------------------------------
    # ATLAS - Impact
    # --------------------------------------------------------

    # AML.T0015
    "BGMSGlucoseModel:evadeAIModel",


    # AML.T0048.000
    "BGMSClinicalImpact:financialHarm",

    # AML.T0048.003
    "BGMSClinicalImpact:userHarm",
]


AUXILIARY_STEPS = {
    "BGMSBluetoothChannel:"
    "attemptTransmittedDataManipulation"
}


# ============================================================
# CREATE MODEL
# ============================================================

def create_model(
    lang_graph: LanguageGraph
) -> Model:

    model = Model(
        "BGMS_URET_ADVERSARIAL_SCENARIO",
        lang_graph
    )


    # ========================================================
    # ATLAS
    # AML.T0016.000
    # ========================================================

    uret_implementation = model.add_asset(
        "AdversarialAttackImplementation",
        "URETImplementation"
    )


    # ========================================================
    # ATT&CK
    # T1588.006
    # ========================================================

    attack_preparation = model.add_asset(
        "AttackPreparation",
        "BGMSAttackPreparation"
    )


    # ========================================================
    # ATT&CK Mobile
    # T1664
    # ========================================================

    bgms_phone = model.add_asset(
        "MobileDevice",
        "BGMSSmartphone"
    )

    bgms_os = model.add_asset(
        "BGMSMobileOS",
        "BGMSSmartphoneOS"
    )


    # ========================================================
    # ATLAS
    # AML.T0035
    # ========================================================

    cgm_artifact = model.add_asset(
        "AIArtifactCollection",
        "CGMArtifact"
    )


    # ========================================================
    # ATLAS
    # AML.T0043
    # ========================================================

    adversarial_cgm = model.add_asset(
        "AdversarialSample",
        "AdversarialCGMReading"
    )


    # ========================================================
    # ATT&CK
    # Bluetooth communication channel
    # ========================================================

    bluetooth_channel = model.add_asset(
        "BGMSBluetoothChannel",
        "BGMSBluetoothChannel"
    )


    # ========================================================
    # ATLAS
    # BGMS predictive model
    # ========================================================

    bgms_model = model.add_asset(
        "PredictiveAIModel",
        "BGMSGlucoseModel"
    )


    # ========================================================
    # ATLAS
    # External impact
    # ========================================================

    clinical_impact = model.add_asset(
        "ExternalHarm",
        "BGMSClinicalImpact"
    )


    # ========================================================
    # ASSOCIATIONS
    # ========================================================


    # --------------------------------------------------------
    # AML.T0016.000
    #       ->
    # T1588.006
    # --------------------------------------------------------

    uret_implementation.add_associated_assets(
        "vulnerabilityPreparation",
        {attack_preparation}
    )


    # --------------------------------------------------------
    # T1588.006
    #       ->
    # T1664
    # --------------------------------------------------------

    attack_preparation.add_associated_assets(
        "mobileDevice",
        {bgms_phone}
    )


    # --------------------------------------------------------
    # Mobile device -> OS
    # --------------------------------------------------------

    bgms_phone.add_associated_assets(
        "os",
        {bgms_os}
    )


    # --------------------------------------------------------
    # T1557
    #       ->
    # AML.T0035
    # --------------------------------------------------------

    bgms_os.add_associated_assets(
        "artifact",
        {cgm_artifact}
    )


    # --------------------------------------------------------
    # AML.T0035
    #       ->
    # AML.T0043
    # --------------------------------------------------------

    cgm_artifact.add_associated_assets(
        "adversarialSample",
        {adversarial_cgm}
    )


    # --------------------------------------------------------
    # AML.T0043
    #       ->
    # T1565.002
    # --------------------------------------------------------

    adversarial_cgm.add_associated_assets(
        "bgmsChannel",
        {bluetooth_channel}
    )


    # --------------------------------------------------------
    # T1565.002
    #       ->
    # AML.T0015
    # --------------------------------------------------------

    bluetooth_channel.add_associated_assets(
        "targetModel",
        {bgms_model}
    )


    # --------------------------------------------------------
    # AML.T0015
    #       ->
    # AML.T0048.000 / AML.T0048.003
    # --------------------------------------------------------

    bgms_model.add_associated_assets(
        "externalHarm",
        {clinical_impact}
    )


    return model


# ============================================================
# DETERMINISTIC ATTACKER
# ============================================================

class BGMSAttacker(DecisionAgent):

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
                "[INFO] BGMS attack path completed."
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
            "[STALLED] BGMS attack path"
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
# VERIFY ATTACK GRAPH
# ============================================================

def verify_nodes(
    attack_graph: AttackGraph
):

    print("\n" + "=" * 70)

    print(
        "VERIFYING BGMS / URET SCENARIO"
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
    # 1. Load MAL language
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
        "\nCreating BGMS model..."
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
    # 4. Verify expected nodes
    # --------------------------------------------------------

    if not verify_nodes(
        attack_graph
    ):

        raise RuntimeError(
            "One or more BGMS attack nodes "
            "are missing."
        )


    # --------------------------------------------------------
    # 5. Configure attacker
    # --------------------------------------------------------

    attacker = AttackerSettings(

        name="BGMS_URET_Attacker",

        entry_points={
            ENTRY_POINT
        },

        # Use User Harm as the terminal goal.
        # Financial Harm is deliberately performed
        # immediately before it by the deterministic path.
        goals={
            "BGMSClinicalImpact:userHarm"
        },

        policy=BGMSAttacker,

        config={
            "attack_path":
                ATTACK_PATH
        }
    )


    # --------------------------------------------------------
    # 6. Create simulator
    # --------------------------------------------------------

    simulator = MalSimulator(

        attack_graph,

        agents=[
            attacker
        ]
    )


    # --------------------------------------------------------
    # 7. Run simulation
    # --------------------------------------------------------

    print("\n" + "=" * 70)

    print(
        "RUNNING BGMS / URET ATTACK SIMULATION"
    )

    print(
        "Defense configuration is read directly from "
        "atlaslang.mal / enterpriselang.mal."
    )

    print("=" * 70)


    actions = run_simulation(
        simulator
    )


    # --------------------------------------------------------
    # 8. Results
    # --------------------------------------------------------

    attacker_actions = actions.get(
        "BGMS_URET_Attacker",
        []
    )


    print("\n" + "=" * 70)

    print(
        "BGMS / URET SCENARIO RESULT"
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
    # Check final impacts
    # --------------------------------------------------------

    performed = {

        node.full_name

        for node in attacker_actions

        if node is not None
    }


    financial_harm = (
        "BGMSClinicalImpact:financialHarm"
        in performed
    )

    user_harm = (
        "BGMSClinicalImpact:userHarm"
        in performed
    )


    print(
        "\nFINAL IMPACTS:"
    )


    print(
        "  AML.T0048.000 Financial Harm: "
        + (
            "REACHED"
            if financial_harm
            else "NOT REACHED"
        )
    )


    print(
        "  AML.T0048.003 User Harm: "
        + (
            "REACHED"
            if user_harm
            else "NOT REACHED"
        )
    )


    print("\n" + "=" * 70)


    if (
        financial_harm
        and user_harm
    ):

        print(
            "[ATTACK SUCCESS] BGMS scenario completed."
        )

        print(
            "The configured MAL defenses did not prevent "
            "the complete historical attack path."
        )

    else:

        print(
            "[ATTACK BLOCKED] One or more final "
            "impacts were not reached."
        )

        print(
            "If one or more defenses are [Enabled] in the MAL "
            "language, this indicates that the defended model "
            "prevented the complete historical path."
        )


    print("=" * 70)


    # --------------------------------------------------------
    # Complete simulator recording
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
