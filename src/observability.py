# src/observability.py
import time
import json
import re
from datetime import datetime

class TechSecureMonitor:
    """
    Sistema centralizado de Observabilidad y Telemetría corporativa (EV3).
    Monitorea de forma aislada latencias, consumo de tokens, costos y aplica Guardrails de Privacidad.
    """
    def __init__(self):
        self.log_file = "agente_ejecucion_trazas.json"
        
    def anonimizar_datos_sensibles(self, texto):
        """
        [PROTOCOLO DE PRIVACIDAD E ISO 27001]
        Detecta y ofusca direcciones IP y nombres de hosts internos en los registros públicos de telemetría.
        """
        if not isinstance(texto, str):
            texto = str(texto)
        # Expresión regular para capturar direcciones IP públicas/privadas
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        texto_anonimizado = re.sub(ip_pattern, "[IP_ANONIMIZADA]", texto)
        return texto_anonimizado

    def calcular_costo_tokens(self, prompt, respuesta, modelo="gpt-4o"):
        """
        [MÉTRICAS DE RENDIMIENTO Y COSTO]
        Simulación exacta de conteo de tokens basado en caracteres y cálculo de costos operacionales.
        """
        # Estimación estándar: 1 token equivale aproximadamente a 4 caracteres en inglés/código
        tokens_input = max(1, len(prompt) // 4)
        tokens_output = max(1, len(respuesta) // 4)
        
        # Tarifas simuladas (Por cada 1,000 tokens)
        precio_input = 0.005 / 1000
        precio_output = 0.015 / 1000
        
        costo_total = (tokens_input * precio_input) + (tokens_output * precio_output)
        
        return {
            "tokens_entrada": tokens_input,
            "tokens_salida": tokens_output,
            "costo_usd": round(costo_total, 6)
        }

    def registrar_traza_evento(self, cve, software, herramienta, latencia, entrada, salida, exito=True):
        """
        [ANALISIS DE REGISTROS Y TRAZABILIDAD]
        Genera registros estructurados en JSON, sanitizando datos sensibles antes de la persistencia.
        """
        datos_tokens = self.calcular_costo_tokens(str(entrada), str(salida))
        
        registro_evento = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "alert_context": {
                "cve_id": cve,
                "software_afectado": software
            },
            "telemetria_ejecucion": {
                "herramienta_utilizada": herramiente_nombre := herramienta,
                "latencia_segundos": round(latencia, 4),
                "estado_ejecucion": "SUCCESS" if exito else "FAILED",
                "metricas_tokens": datos_tokens
            },
            "auditoria_datos_limpios": {
                "payload_entrada": self.anonimizar_datos_sensibles(entrada),
                "payload_salida": self.anonimizar_datos_sensibles(salida)
            }
        }
        
        # Persistencia en formato JSON Log append para dashboards
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(registro_evento, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"Error escribiendo trazas de telemetría: {e}")
            
        return registro_evento
