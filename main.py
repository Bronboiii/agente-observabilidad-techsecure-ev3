import argparse
import time
import json
from src.observability import TechSecureMonitor

class AgenteMemory:
    def __init__(self):
        self.corto_plazo = {"historial_pasos": [], "activo_identificado": None, "analisis_contextual": None}
        self.largo_plazo_cache = {"falsos_positivos_historicos": ["CVE-2021-9999", "CVE-2022-0001"]}

# Inicialización global del monitor de observabilidad de la EV3
monitor = TechSecureMonitor()

def tool_asset_lookup(cve_id, software_alerta, memory):
    """Herramienta de búsqueda de activos instrumentalizada con telemetría."""
    tiempo_inicio = time.time()
    
    inventario_csv = [
        {"host": "srv-produccion-web", "ip": "192.168.1.50", "software": "Apache httpd", "entorno": "DMZ"},
        {"host": "srv-desarrollo-bd", "ip": "10.0.2.15", "software": "PostgreSQL", "entorno": "Desarrollo"}
    ]
    
    time.sleep(0.35)  # Simulación de latencia de red
    activo_encontrado = None
    for activo in inventario_csv:
        if activo["software"].lower() in software_alerta.lower():
            activo_encontrado = activo
            break
            
    latencia_total = time.time() - tiempo_inicio
    
    # Registro automático de la traza de observabilidad
    monitor.registrar_traza_evento(
        cve=cve_id,
        software=software_alerta,
        herramienta="Asset_Lookup_Tool",
        latencia=latencia_total,
        entrada=f"Query: {software_alerta}",
        salida=activo_encontrado if activo_encontrado else "No_Asset_Found"
    )
    return activo_encontrado


def tool_rag_retrieval(cve_id, software, entorno_red, memory):
    """Herramienta RAG instrumentalizada con telemetría."""
    tiempo_inicio = time.time()
    
    time.sleep(0.52)  # Simulación de búsqueda semántica en base vectorial
    if entorno_red == "DMZ":
        resultado_rag = {
            "politica_seguridad": "Zona expuesta (DMZ) exige aislamiento inmediato. Parcheo obligatorio < 24 horas.",
            "playbook_sugerido": "Aislar puerto afectado en firewall y actualizar servicio.",
            "origen_metadatos": "Politica_Seguridad_TechSecure.pdf (Chunk #14)"
        }
    else:
        resultado_rag = {
            "politica_seguridad": "Entorno interno de pruebas. Mitigación por IPTables permitida y ventana mensual.",
            "playbook_sugerido": "Aplicar regla local IPTables y agendar parcheo.",
            "origen_metadatos": "Manual_Operaciones_SOC.md (Chunk #22)"
        }
        
    latencia_total = time.time() - tiempo_inicio
    
    # Registro automático de la traza de observabilidad
    monitor.registrar_traza_evento(
        cve=cve_id,
        software=software,
        herramienta="RAG_Retrieval_Tool",
        latencia=latencia_total,
        entrada=f"Context: {cve_id} + Network: {entorno_red}",
        salida=resultado_rag
    )
    return resultado_rag


def ejecutar_agente_supervisor_ev3(cve_id, software_alerta):
    tiempo_inicio_global = time.time()
    memory = AgenteMemory()
    
    print(f"\n [SOC AUTOMATION]: Iniciando triaje instrumentalizado para {cve_id}...")
    
    # Excepción por caché histórico de la memoria a largo plazo
    if cve_id in memory.largo_plazo_cache["falsos_positivos_historicos"]:
        latencia_fp = time.time() - tiempo_inicio_global
        monitor.registrar_traza_evento(cve_id, software_alerta, "Memoria_Largo_Plazo_Bypass", latencia_fp, "Check Cache", "Falso Positivo Cerrado Automáticamente")
        print(f" [TELEMETRÍA]: Alerta resuelta mediante memoria histórica en {round(latencia_fp, 4)} segundos.")
        return

    # Fase 1: Búsqueda de activo
    activo = tool_asset_lookup(cve_id, software_alerta, memory)
    if not activo:
        latencia_abort = time.time() - tiempo_inicio_global
        print(f" [TELEMETRÍA]: Triaje finalizado anticipadamente. Activo no existente en infraestructura.")
        return

    # Fase 2: Recuperación RAG
    entorno = activo["entorno"]
    contexto_rag = tool_rag_retrieval(cve_id, software_alerta, entorno, memory)
    
    latencia_total_agente = time.time() - tiempo_inicio_global
    print(f" [TELEMETRÍA]: Ciclo completo del agente cerrado con éxito.")
    print(f" Latencia de Ejecución Extremo a Extremo: {round(latencia_total_agente, 4)} seg.")
    print(f" Traza limpia almacenada en: 'agente_ejecucion_trazas.json' de forma segura.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Framework de Agente Supervisor con Observabilidad Avanzada - EV3")
    parser.add_argument("--cve", default="CVE-2024-1234")
    parser.add_argument("--software", default="Apache httpd")
    args = parser.parse_args()
    
    ejecutar_agente_supervisor_ev3(args.cve, args.software)
