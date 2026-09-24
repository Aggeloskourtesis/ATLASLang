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
# CT-GAN SCENARIO
# ============================================================

ENTRY_POINT = (
    "CTGANCapability:adversarialAIAttacks"
)


ATTACK_PATH = [

    # --------------------------------------------------------
    # ATT&CK - Resource Development
    # --------------------------------------------------------

    # T1587.001
    "CTGANAttackPreparation:developMalware",

    # T1588.002
    "CTGANAttackPreparation:obtainTool",


    # --------------------------------------------------------
    # ATT&CK - Reconnaissance
    # --------------------------------------------------------

    # T1591.003
    "HospitalRecon:identifyBusinessTempo",

    # T1591.001
    "HospitalRecon:determinePhysicalLocations",


    # --------------------------------------------------------
    # Internal enterpriseLang prerequisite
    # Not a separate technique in the case-study table
    # --------------------------------------------------------

    "RaspberryPiBridge:physicalAccess",


    # --------------------------------------------------------
    # ATT&CK - Initial Access
    # --------------------------------------------------------

    # T1200
    "RaspberryPiBridge:hardwareAdditions",

    # T1669
    "HospitalImagingNetwork:wiFiNetworks",


    # --------------------------------------------------------
    # ATT&CK - Collection
    # --------------------------------------------------------

    # T1557
    "RaspberryPiOS:manInTheMiddle",

    # T1005
    "RaspberryPiOS:dataFromLocalSystem",


    # --------------------------------------------------------
    # ATLAS - AI Attack Staging
    # --------------------------------------------------------

    # AML.T0043
    "TamperedDICOM:craftAdversarialData",


    # --------------------------------------------------------
    # Internal enterpriseLang step
    # --------------------------------------------------------

    "HospitalImagingNetwork:"
    "attemptTransmittedDataManipulation",


    # --------------------------------------------------------
    # ATT&CK - Impact
    # --------------------------------------------------------

    # T1565.002
    "HospitalImagingNetwork:"
    "transmittedDataManipulation",


    # --------------------------------------------------------
    # ATLAS - Impact
    # --------------------------------------------------------

    # AML.T0015
    "LungCancerScreeningModel:evadeAIModel",


    # AML.T0048.000
    "ClinicalImpact:financialHarm",

    # AML.T0048.003
    "ClinicalImpact:userHarm",
]


# Nodes that exist only because of enterpriseLang's internal
# attack-step structure.
AUXILIARY_STEPS = {
    "RaspberryPiBridge:physicalAccess",
    "HospitalImagingNetwork:"
    "attemptTransmittedDataManipulation",
}


# ============================================================
# CREATE MODEL
# ============================================================

def create_model(lang_graph: LanguageGraph) -> Model:

    model = Model(
        "CT_GAN_MEDICAL_IMAGING_SCENARIO",
        lang_graph
    )


    # ========================================================
    # ATLAS: CT-GAN capability
    # ========================================================

    ctgan_capability = model.add_asset(
        "AdversarialCapability",
        "CTGANCapability"
    )


    # ========================================================
    # ATT&CK: Resource Development
    # ========================================================

    attack_preparation = model.add_asset(
        "AttackPreparation",
        "CTGANAttackPreparation"
    )


    # ========================================================
    # ATT&CK: Reconnaissance
    # ========================================================

    hospital_recon = model.add_asset(
        "VictimOrganizationRecon",
        "HospitalRecon"
    )


    # ========================================================
    # Raspberry Pi passive bridge
    # ========================================================

    raspberry_pi = model.add_asset(
        "HardwareAddition",
        "RaspberryPiBridge"
    )

    raspberry_pi_os = model.add_asset(
        "CTAttackOS",
        "RaspberryPiOS"
    )


    # ========================================================
    # Hospital imaging network
    # ========================================================

    hospital_router = model.add_asset(
        "Router",
        "HospitalImagingRouter"
    )

    imaging_network = model.add_asset(
        "CTImageNetwork",
        "HospitalImagingNetwork"
    )


    # ========================================================
    # Optional infrastructure assets
    # These make the system model closer to the real scenario.
    # ========================================================

    ct_scanner = model.add_asset(
        "Computer",
        "CTScanner"
    )

    ct_scanner_os = model.add_asset(
        "OS",
        "CTScannerOS"
    )

    pacs_server = model.add_asset(
        "Computer",
        "PACSServer"
    )

    pacs_os = model.add_asset(
        "OS",
        "PACSServerOS"
    )


    # ========================================================
    # ATLAS: Adversarial DICOM image
    # ========================================================

    tampered_dicom = model.add_asset(
        "AdversarialSample",
        "TamperedDICOM"
    )


    # ========================================================
    # ATLAS: Lung-cancer screening model
    # ========================================================

    lung_cancer_model = model.add_asset(
        "AIMalwareDetector",
        "LungCancerScreeningModel"
    )


    # ========================================================
    # ATLAS: Clinical impact
    # ========================================================

    clinical_impact = model.add_asset(
        "ExternalHarm",
        "ClinicalImpact"
    )


    # ========================================================
    # ASSOCIATIONS
    # ========================================================

    # AML.T0017.000
    #   ->
    # T1587.001
    ctgan_capability.add_associated_assets(
        "attackPreparation",
        {attack_preparation}
    )


    # T1588.002
    #   ->
    # T1591.003
    attack_preparation.add_associated_assets(
        "victimRecon",
        {hospital_recon}
    )


    # T1591.001
    #   ->
    # physical access / T1200
    hospital_recon.add_associated_assets(
        "hardwareAddition",
        {raspberry_pi}
    )


    # Raspberry Pi runs our CT-specific OS
    raspberry_pi.add_associated_assets(
        "os",
        {raspberry_pi_os}
    )


    # Raspberry Pi is connected through hospital router
    raspberry_pi.add_associated_assets(
        "router",
        {hospital_router}
    )


    # Imaging network belongs to the router
    hospital_router.add_associated_assets(
        "internalNetwork",
        {imaging_network}
    )


    # --------------------------------------------------------
    # CT scanner
    # --------------------------------------------------------

    ct_scanner.add_associated_assets(
        "os",
        {ct_scanner_os}
    )

    ct_scanner.add_associated_assets(
        "router",
        {hospital_router}
    )


    # --------------------------------------------------------
    # PACS server
    # --------------------------------------------------------

    pacs_server.add_associated_assets(
        "os",
        {pacs_os}
    )

    pacs_server.add_associated_assets(
        "router",
        {hospital_router}
    )


    # --------------------------------------------------------
    # T1005 -> AML.T0043
    # --------------------------------------------------------

    raspberry_pi_os.add_associated_assets(
        "ctImage",
        {tampered_dicom}
    )


    # --------------------------------------------------------
    # AML.T0043 -> T1565.002
    # --------------------------------------------------------

    tampered_dicom.add_associated_assets(
        "ctNetwork",
        {imaging_network}
    )


    # --------------------------------------------------------
    # T1565.002 -> AML.T0015
    # --------------------------------------------------------

    imaging_network.add_associated_assets(
        "targetModel",
        {lung_cancer_model}
    )


    # --------------------------------------------------------
    # AML.T0015 -> AML.T0048.000 / AML.T0048.003
    # --------------------------------------------------------

    lung_cancer_model.add_associated_assets(
        "externalHarm",
        {clinical_impact}
    )


    return model


# ============================================================
# DETERMINISTIC ATTACKER
# ============================================================

class CTGANAttacker(DecisionAgent):

    def __init__(self, agent_config, **_):

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
                "[INFO] CT-GAN attack path completed."
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

            return action_surface[next_step]


        # ----------------------------------------------------
        # Debug information if path stalls
        # ----------------------------------------------------

        print("\n" + "=" * 70)

        print(
            "[STALLED] CT-GAN attack path"
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


        print("\nCurrent action surface:")

        for node in sorted(action_surface):

            print(
                f"  {node}"
            )


        print("=" * 70)


        raise RuntimeError(
            "CT-GAN attack path stalled at: "
            f"{next_step}"
        )


# ============================================================
# VERIFY NODES
# ============================================================

def verify_nodes(
    attack_graph: AttackGraph
):

    print("\n" + "=" * 70)

    print(
        "VERIFYING CT-GAN SCENARIO"
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
        "\nCreating CT-GAN model..."
    )

    model = create_model(
        lang_graph
    )

    print(
        "Model created successfully."
    )


    # --------------------------------------------------------
    # 3. Attack graph
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
            "One or more CT-GAN attack nodes "
            "are missing."
        )


    # --------------------------------------------------------
    # 5. Configure attacker
    # --------------------------------------------------------

    attacker = AttackerSettings(

        name="CT_GAN_Attacker",

        entry_points={
            ENTRY_POINT
        },

        # Use user harm as the terminal simulator goal.
        # Financial harm is still deliberately performed first
        # by the deterministic path.
        goals={
            "ClinicalImpact:userHarm"
        },

        policy=CTGANAttacker,

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
        agents=[attacker]
    )


    # --------------------------------------------------------
    # 7. Run
    # --------------------------------------------------------

    print("\n" + "=" * 70)

    print(
        "RUNNING CT-GAN ATTACK SIMULATION"
    )

    print("=" * 70)


    actions = run_simulation(
        simulator
    )


    # --------------------------------------------------------
    # 8. Results
    # --------------------------------------------------------

    attacker_actions = actions.get(
        "CT_GAN_Attacker",
        []
    )


    print("\n" + "=" * 70)

    print(
        "CT-GAN SCENARIO RESULT"
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

        if node.full_name in AUXILIARY_STEPS:
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
        "ClinicalImpact:financialHarm"
        in performed
    )

    user_harm = (
        "ClinicalImpact:userHarm"
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
            "[SUCCESS] CT-GAN scenario completed."
        )

    else:

        print(
            "[FAILED] One or more final impacts "
            "were not reached."
        )


    print("=" * 70)


    # --------------------------------------------------------
    # Complete recording
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
