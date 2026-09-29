# Active Directory: evaluar, endurecer y validar

> **Resumen** — Diseño de referencia de un trabajo defensivo sobre Active Directory en una empresa ficticia de 40
> personas: once debilidades típicas de pequeñas empresas, un plan de evaluación con PingCastle, BloodHound CE y
> la línea base de seguridad de Microsoft, endurecimiento entregado como PowerShell idempotente que se niega a
> ejecutarse fuera del dominio del laboratorio, y herramientas que convierten los escaneos de antes y después en
> un registro de hallazgos y un informe profesional. **Entregable: diseño de referencia, listo para construir.**

![Diagrama de arquitectura](diagrams/architecture.svg)

| | |
|---|---|
| **Rol asumido** | Consultor de seguridad que evalúa y endurece el dominio de una pequeña empresa |
| **Entorno** | `corp.internal` en Proxmox: un DC, un servidor miembro y dos estaciones (red de los Labs 01–02) |
| **Herramientas** | PingCastle, BloodHound CE, Microsoft Security Compliance Toolkit, PowerShell, Pester, Python |
| **Entregable** | Catálogo de debilidades, guías de evaluación, 9 scripts de endurecimiento, registro de hallazgos, generador de informes |

---

## 1. Problema

- **Contexto:** una empresa ficticia de servicios profesionales cuyo dominio creció "con lo que funcionara": una
  cuenta de servicio en Domain Admins, la misma contraseña de administrador local en todos los equipos,
  protocolos antiguos activos y administradores que usan la misma cuenta para el correo y para el controlador de
  dominio.
- **Por qué importa:** en Active Directory, un eslabón débil suele llevar a todo. Una sola estación o servicio
  comprometido puede terminar en el control total del dominio.
- **Objetivos:**
    1. Encontrar las debilidades con herramientas de auditoría reconocidas y de solo lectura.
    2. Calificar cada una por su riesgo para el negocio y registrarla con evidencia.
    3. Corregirlas de forma repetible, revisable y segura de volver a ejecutar.
    4. Demostrar las correcciones con las mismas herramientas y confirmar que el SIEM ve los cambios importantes.
- **Restricciones:** solo laboratorio aislado; herramientas gratuitas; sin explotación. La historia es
  *encontrado → corregido → demostrado*.
- **Criterios de éxito:** cada hallazgo cerrado o aceptado conscientemente con verificación; menor puntaje de
  riesgo en PingCastle; ninguna ruta a Domain Admins en BloodHound; eventos clave visibles en Wazuh.

## 2. Arquitectura

| Host | SO | Zona / IP | Función |
|---|---|---|---|
| dc01 | Windows Server 2022 | SERVERS · 10.10.20.11 | Controlador de dominio y DNS (Nivel 0) |
| app01 | Windows Server 2022 | SERVERS · 10.10.20.13 | Servidor de archivos y aplicaciones (Nivel 1) |
| ws01 | Windows 11 | USERS · 10.10.30.21 | Estación de trabajo (Nivel 2) |
| ws02 | Windows 11 | USERS · 10.10.30.22 | Estación de trabajo (Nivel 2) |

| Decisión | Alternativas consideradas | Por qué esta |
|---|---|---|
| `corp.internal` | `lab.local`; un subdominio de un dominio real | `.internal` está reservado por la ICANN para uso privado; `.local` choca con mDNS |
| Debilidades aplicadas a mano desde un catálogo | Un script que las cree | El repositorio solo automatiza correcciones; la lista sirve además como checklist para evaluaciones reales |
| Un script de PowerShell por control | Un único script grande | Cada control se revisa, se prueba y se despliega por separado |
| Protección contra el dominio equivocado | Confiar en el operador | Un script copiado a una red real se niega a ejecutarse salvo que se fuerce |
| Registro de hallazgos en YAML | Una hoja de cálculo | El mismo archivo genera la tabla de hallazgos y el informe; "corregido" exige prueba |

## 3. Construcción

1. [Construir el dominio](docs/build.md): promover dc01, unir los miembros y ejecutar `New-LabDomainStructure.ps1`.
2. [Aplicar las debilidades de partida](docs/weaknesses.md) W01–W11 y tomar un snapshot de las VM.
3. Hacer la evaluación **inicial** ([PingCastle](docs/assessment/01-pingcastle.md),
   [BloodHound CE](docs/assessment/02-bloodhound.md), [Policy Analyzer](docs/assessment/03-policy-analyzer.md)) y
   registrar la evidencia en [findings/findings.yaml](findings/findings.yaml).
4. Endurecer, revisando cada script primero con `-WhatIf` (la tabla de scripts está en la versión en inglés).
5. Hacer la evaluación **final**, actualizar los hallazgos, ejecutar las [verificaciones del SIEM](docs/siem-checks.md)
   y generar el informe: `python -m adlab.report --pdf`.

## 4. Plan de evaluación

- **PingCastle** da la cifra principal: un puntaje de riesgo que debe bajar tras el endurecimiento.
- **BloodHound CE** muestra *relaciones*: la cuenta de servicio, la delegación del helpdesk y las sesiones de
  administradores en estaciones deben aparecer como rutas a Domain Admins antes, y desaparecer después.
- **Policy Analyzer** compara las políticas aplicadas con la línea base de Microsoft.
- **Wazuh (Lab 01)** debe mostrar cambios de grupos, inicios de sesión fallidos, bloqueos y lecturas de
  contraseñas LAPS ([docs/siem-checks.md](docs/siem-checks.md)).

## 5. Entregables y medición

**Entregado en este repositorio:**

- Un catálogo de once debilidades con por qué son comunes, cómo reproducirlas y qué herramienta las detecta.
- Nueve scripts de endurecimiento y uno de construcción del dominio: idempotentes, compatibles con `-WhatIf`,
  que registran cada cambio y se niegan a ejecutarse fuera de `corp.internal`. Cada uno tiene pruebas Pester 5
  (61, que pasan en CI junto con PSScriptAnalyzer sin hallazgos) que ejecutan los scripts contra cmdlets de AD
  simulados; detectaron un error por el que `-WhatIf` no llegaba a una función compartida.
- Un registro de hallazgos que rechaza "corregido" sin prueba, un analizador del puntaje de PingCastle y un
  generador de informes que se mantiene como *Borrador* hasta que existan escaneos reales de antes y después.

**Cómo se miden los resultados:**

| Métrica | Fuente |
|---|---|
| Puntaje global y parciales de PingCastle, antes → después | `python -m adlab.scores` |
| Hallazgos corregidos / aceptados con verificación | `python -m adlab.findings findings/findings.yaml` |
| Rutas a Domain Admins, antes → después | BloodHound CE |
| Verificaciones del SIEM superadas | [tests/test-plan.md](tests/test-plan.md) |

## 6. Lecciones de diseño y hoja de ruta

- **Automatiza la corrección, no la falla.** El repositorio no contiene código que debilite un dominio, lo que lo
  hace seguro de publicar y permite reutilizar el catálogo como checklist de auditoría.
- **Haz confiable la vista previa.** `-WhatIf` solo sirve si es fiable: las variables de preferencia no pasan a
  las funciones de un módulo de PowerShell, así que una función compartida hacía cambios durante la vista previa
  hasta que la llamada pasó `-WhatIf` de forma explícita. Probar la propia vista previa lo encontró.
- **Limita el radio de impacto.** Cada script comprueba que se ejecuta contra el dominio del laboratorio, incluidos
  nombres parecidos como `xcorp.internal`, antes de tocar nada.
- **No todo cabe en los cmdlets cómodos.** Las asignaciones de derechos de usuario (las denegaciones de inicio de
  sesión por nivel) no se pueden fijar con los cmdlets de GPO basados en registro y requieren la plantilla de
  seguridad de la GPO; ese script es el que más revisión necesita.
- **Los sustitutos deben cubrirlo todo.** Dos cmdlets de AD no tenían sustituto de prueba; en un equipo con las
  herramientas de administración instaladas las pruebas llamaban en silencio a los reales, y solo CI, sin ellas,
  falló. Ahora una prueba verifica que cada comando de AD y de directivas de grupo que usan los scripts tenga
  sustituto.
- **"Corregido" necesita prueba.** El registro rechaza un hallazgo corregido sin `verified_by` y el informe sigue
  como borrador hasta que existe el escaneo final.

**Correcciones de la revisión:** una revisión de los scripts encontró problemas: el archivo de versión de la GPO
en la carpeta equivocada, opciones de seguridad que las directivas predeterminadas del dominio sobrescribirían,
la directiva de contraseñas fijada donde la Default Domain Policy la revertiría, la clave y el cifrado de LAPS, y
los servidores miembro compartiendo los lectores de LAPS de las estaciones. Están corregidos y cubiertos por
pruebas, y las pruebas Pester pasan en CI. Aún no se han ejecutado contra un dominio real: el
[plan de pruebas](tests/test-plan.md) lista las verificaciones para eso.

**Hoja de ruta:** construir el laboratorio, hacer las evaluaciones de antes y después, publicar el cambio medido
del puntaje y ampliar con el endurecimiento de Active Directory Certificate Services.

## 7. Reprodúcelo tú mismo

- Clonar: `git clone https://github.com/santorest/lab-03-ad-assess-harden.git`
- Descargar el paquete: desde el sitio del portafolio (el SHA-256 aparece junto a la descarga).
- Tiempo estimado: 2–3 días, incluidas ambas evaluaciones.
- Limpieza: volver al snapshot de línea base limpia o eliminar las VM.

## 8. Mapeo

| Control | Marco | Cómo lo aborda este proyecto |
|---|---|---|
| 5.4 Restringir privilegios de administrador a cuentas dedicadas | CIS Controls v8 | Modelo de administración por niveles, restricciones de inicio de sesión del Nivel 0 |
| 5.2 Usar contraseñas únicas | CIS Controls v8 | Windows LAPS, gMSA |
| 5.3 Deshabilitar cuentas inactivas | CIS Controls v8 | Revisión de cuentas obsoletas |
| 4.1 Establecer un proceso de configuración segura | CIS Controls v8 | Línea base de Microsoft, protocolos antiguos desactivados, firma LDAP |
| 6.8 Control de acceso basado en roles | CIS Controls v8 | Delegación del helpdesk limitada a las OU de usuarios |
| PR.AA Gestión de identidades, autenticación y control de acceso | NIST CSF 2.0 | Los controles de identidad anteriores |

---

*Todas las pruebas se realizan en un entorno de laboratorio aislado de mi propiedad. No se incluyen datos,
nombres de host ni configuraciones de ninguna organización real.*
