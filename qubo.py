"""QUBO para seleccionar acciones de remediación bajo presupuesto.

El QUBO suma tres partes: el beneficio OR de cada vulnerabilidad (con signo negativo),
la penalización del presupuesto y la penalización de cada regla.

El QUBO se guarda como un diccionario Q[(u, v)] más una constante.
Los términos lineales van en Q[(v, v)].

La explicación del código y de las fórmulas está en QUBO.md.
"""

from collections import defaultdict
import dimod

def pesos_holgura(m):
    """Pesos de los bits que representan una holgura entera entre 0 y m.

    Ejemplos: m=2 -> [1, 1], m=3 -> [1, 2], m=5 -> [1, 2, 2], m=7 -> [1, 2, 4].
    """
    if m == 0:
        return []
    k = m.bit_length()
    return [2**j for j in range(k - 1)] + [m + 1 - 2 ** (k - 1)]


def _sumar(Q, u, v, c):
    """Suma un coeficiente al término de dos variables del QUBO.

    Args:
        Q: diccionario del QUBO, {(variable, variable): coeficiente}.
        u: nombre de la primera variable (por ejemplo "x_a1").
        v: nombre de la segunda variable. Si es la misma que u, el término es lineal.
        c: coeficiente que se suma.
    """
    clave = (u, v) if u <= v else (v, u)
    Q[clave] += c


def _sumar_cuadrado(Q, lineal, constante, factor):
    """Suma al QUBO el cuadrado de una expresión lineal multiplicado por factor.

    La expresión es la constante más cada variable de lineal por su coeficiente.
    Devuelve la parte constante del cuadrado, que no se guarda en Q.
    """
    variables = list(lineal.items())
    for i, (u, a) in enumerate(variables):
        _sumar(Q, u, u, factor * (a * a + 2 * constante * a))
        for v, b in variables[i + 1 :]:
            _sumar(Q, u, v, factor * 2 * a * b)
    return factor * constante * constante


def construir_qubo(acciones, presupuesto, vulnerabilidades, reglas, lam=None):
    """Construye el QUBO general.

    Args:
        acciones: dict {nombre_accion: coste entero}.
        presupuesto: presupuesto entero B.
        vulnerabilidades: lista de (peso, [acciones que la corrigen]).
        reglas: lista de (L, R): si se eligen todas las de L, hay que elegir alguna de R.
        lam: peso de las penalizaciones. Por defecto, la suma de los pesos más uno.

    Returns:
        (Q, constante, lam). La energía de una asignación es la constante más la suma
        de cada coeficiente de Q por sus dos variables.
        Las variables de decisión se llaman "x_<accion>".
    """
    if lam is None:
        lam = sum(peso for peso, _ in vulnerabilidades) + 1
    Q = defaultdict(float)
    constante = 0.0

    # 1. Beneficio OR de cada vulnerabilidad.
    for i, (peso, acc) in enumerate(vulnerabilidades, start=1):
        x = [f"x_{a}" for a in acc]
        if peso == 0 or not x:
            continue
        _sumar(Q, x[0], x[0], -peso)
        if len(x) >= 2:
            _sumar(Q, x[1], x[1], -peso)
            _sumar(Q, x[0], x[1], peso)
        for k in range(3, len(x) + 1):  # auxiliares y_3 ... y_d
            y = f"y_{i}_{k}"
            for xj in x[: k - 1]:
                _sumar(Q, y, xj, peso)
            _sumar(Q, y, x[k - 1], -peso)

    # 2. Penalización del presupuesto.
    lineal = {f"x_{a}": coste for a, coste in acciones.items()}
    for j, w in enumerate(pesos_holgura(presupuesto), start=1):
        lineal[f"zB_{j}"] = w
    constante += _sumar_cuadrado(Q, lineal, -presupuesto, lam)

    # 3. Penalización de cada regla.
    for r, (L, R) in enumerate(reglas, start=1):
        lineal = {f"x_{a}": -1 for a in L}
        lineal.update({f"x_{b}": 1 for b in R})
        for j, w in enumerate(pesos_holgura(len(L) + len(R) - 1), start=1):
            lineal[f"z_{r}_{j}"] = -w
        constante += _sumar_cuadrado(Q, lineal, len(L) - 1, lam)

    Q = {clave: c for clave, c in Q.items() if c != 0}
    return Q, constante, lam


def construir_bqm(acciones, presupuesto, vulnerabilidades, reglas, lam=None):
    """Igual que construir_qubo, pero devuelve un dimod.BinaryQuadraticModel."""
    Q, constante, _ = construir_qubo(acciones, presupuesto, vulnerabilidades, reglas, lam)
    return dimod.BinaryQuadraticModel.from_qubo(Q, offset=constante)


def cartera(muestra):
    """Acciones elegidas en una muestra (las variables x_<accion> que valen 1)."""
    return sorted(v[2:] for v, valor in muestra.items() if v.startswith("x_") and valor == 1)