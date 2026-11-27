import dimod
from qubo import cartera, construir_bqm


def main():
    acciones = {"a1": 4, "a2": 1, "a3": 3, "a4": 2, "a5": 1, "a6": 1}
    presupuesto = 7
    vulnerabilidades = [
        (10, ["a1", "a2"]),
        (6, ["a1", "a3", "a6"]),
        (12, ["a3", "a5"]),
        (8, ["a2", "a4"]),
    ]
    reglas = [
        (["a1", "a6"], []),
        (["a5"], ["a2"]),
        (["a3"], ["a1", "a2"]),
        (["a2", "a3", "a4"], []),
        (["a2", "a4"], ["a5", "a6"]),
    ]

    bqm = construir_bqm(acciones, presupuesto, vulnerabilidades, reglas)
    mejor = dimod.ExactSolver().sample(bqm).first
    print(f"Variables: {bqm.num_variables}, interacciones: {bqm.num_interactions}")
    print(f"Mejor cartera: {cartera(mejor.sample)}, energía: {mejor.energy}")


if __name__ == "__main__":
    main()