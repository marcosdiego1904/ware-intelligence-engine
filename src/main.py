import pandas as pd
import os
import re
import fnmatch
import argparse 
from datetime import datetime, timedelta

def load_data(inventory_path, rules_path):
    """
    Carga los datos de los archivos Excel de inventario y reglas.
    """
    try:
        inventory_df = pd.read_excel(inventory_path, parse_dates=['creation_date'])
        rules_df = pd.read_excel(rules_path)
        print(f"✅ Archivo de inventario '{os.path.basename(inventory_path)}' cargado.")
        print(f"✅ Archivo de reglas '{os.path.basename(rules_path)}' cargado.")
        return inventory_df, rules_df
    except FileNotFoundError as e:
        print(f"❌ ERROR: No se encontró el archivo - {e}")
        return None, None
    except Exception as e:
        print(f"❌ ERROR: Ocurrió un error inesperado al cargar los datos - {e}")
        return None, None

def get_rule_for_location(location, rules_df):
    """
    Encuentra la regla de negocio que corresponde a una ubicación específica.
    Ahora es insensible a mayúsculas/minúsculas.
    """
    if not isinstance(location, str): return None 
    location = location.strip()
    
    for index, rule in rules_df.iterrows():
        pattern = rule['location_pattern'].replace('*', '.*')
        # MEJORA: Añadimos re.IGNORECASE para que la coincidencia no distinga mayúsculas/minúsculas.
        regex = f"^{pattern}$"
        if re.match(regex, location, re.IGNORECASE):
            return rule
    return None

# --- NUEVA DETECCIÓN 6: UBICACIÓN FALTANTE ---
def detect_missing_locations(inventory_df, debug=False):
    """
    Detección 6: Encuentra pallets sin ninguna ubicación asignada.
    """
    anomalies = []
    # Filtramos para encontrar pallets donde el tipo de ubicación es 'FALTANTE'.
    missing_loc_pallets = inventory_df[inventory_df['location_type'] == 'FALTANTE']
    
    if debug and not missing_loc_pallets.empty:
        print("  [DEBUG D6] Pallets encontrados con ubicación faltante.")

    for index, pallet in missing_loc_pallets.iterrows():
        anomalies.append({
            'pallet_id': pallet['pallet_id'], 'location': 'N/A',
            'anomaly_type': 'Ubicación Faltante', 'priority': 'MUY ALTA',
            'details': "El pallet no tiene ninguna ubicación registrada en el reporte."
        })
    return anomalies

def detect_floating_pallets(inventory_df, hours_threshold=8, debug=False):
    """
    Detección 1: Encuentra pallets en 'RECEIVING' por más tiempo del permitido.
    """
    anomalies = []
    now = datetime.now()
    receiving_pallets = inventory_df[inventory_df['location'] == 'RECEIVING']
    for index, pallet in receiving_pallets.iterrows():
        time_in_receiving = now - pallet['creation_date']
        if debug:
            print(f"  [DEBUG D1] Pallet {pallet['pallet_id']} en RECEIVING por {time_in_receiving.total_seconds()/3600:.2f}h. Umbral: {hours_threshold}h.")
        if time_in_receiving > timedelta(hours=hours_threshold):
            anomalies.append({
                'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                'anomaly_type': 'Pallet Flotante', 'priority': 'ALTA',
                'details': f"El pallet ha estado en RECEIVING por más de {hours_threshold} horas ({time_in_receiving.total_seconds()/3600:.2f}h)."
            })
    return anomalies

def detect_lot_stragglers(inventory_df, rules_df, completion_threshold=0.85, debug=False):
    """
    Detección 2: Encuentra pallets rezagados de lotes casi completos.
    """
    anomalies = []
    lots = inventory_df.groupby('receipt_number')
    for receipt_number, lot_df in lots:
        final_pallets = lot_df[lot_df['location_type'] == 'FINAL'].shape[0]
        total_pallets = lot_df.shape[0]
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D2] Lote '{receipt_number}': Ratio={completion_ratio:.2f}, Umbral={completion_threshold}")
        if completion_ratio >= completion_threshold:
            stragglers = lot_df[lot_df['location_type'] == 'RECEIVING']
            for index, pallet in stragglers.iterrows():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Rezagado de Lote', 'priority': 'MUY ALTA',
                    'details': f"El {completion_ratio:.0%} del lote '{receipt_number}' ya fue almacenado, pero este pallet sigue en recepción."
                })
    return anomalies

def detect_stuck_in_transit_pallets(inventory_df, rules_df, lot_completion_threshold=0.80, hours_threshold=6, debug=False):
    """
    Detección 3: Encuentra pallets atascados en ubicaciones de tránsito.
    """
    anomalies = []
    now = datetime.now()
    lots = inventory_df.groupby('receipt_number')
    for receipt_number, lot_df in lots:
        final_pallets = lot_df[lot_df['location_type'] == 'FINAL'].shape[0]
        total_pallets = lot_df.shape[0]
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D3-Lote] Lote '{receipt_number}': Ratio={completion_ratio:.2f}, Umbral={lot_completion_threshold}")
        if completion_ratio >= lot_completion_threshold:
            stuck_pallets = lot_df[lot_df['location_type'] == 'TRANSITIONAL']
            for index, pallet in stuck_pallets.iterrows():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Atascado en Tránsito (Lote Completo)', 'priority': 'ALTA',
                    'details': f"El {completion_ratio:.0%} del lote '{receipt_number}' ya fue almacenado, pero este pallet sigue en una ubicación de tránsito."
                })
    transitional_pallets = inventory_df[inventory_df['location_type'] == 'TRANSITIONAL']
    for index, pallet in transitional_pallets.iterrows():
        time_in_transit = now - pallet['creation_date']
        if debug:
            print(f"  [DEBUG D3-Tiempo] Pallet {pallet['pallet_id']} en Tránsito por {time_in_transit.total_seconds()/3600:.2f}h. Umbral: {hours_threshold}h.")
        if time_in_transit > timedelta(hours=hours_threshold):
            if not any(d['pallet_id'] == pallet['pallet_id'] for d in anomalies):
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Atascado en Tránsito (Tiempo Excedido)', 'priority': 'MEDIA',
                    'details': f"El pallet ha estado en una ubicación de tránsito por más de {hours_threshold} horas ({time_in_transit.total_seconds()/3600:.2f}h)."
                })
    return anomalies

def detect_incompatibility_and_overcapacity(inventory_df, rules_df, debug=False):
    """
    Detección 4: Encuentra pallets incompatibles y ubicaciones sobre-saturadas.
    Ahora es insensible a mayúsculas/minúsculas.
    """
    anomalies = []
    # Usamos una copia para no modificar el DataFrame original al convertir a mayúsculas.
    temp_df = inventory_df.copy()
    temp_df['location_upper'] = temp_df['location'].str.upper()
    
    location_counts = temp_df['location_upper'].value_counts().reset_index()
    location_counts.columns = ['location_upper', 'pallet_count']
    
    for index, loc_info in location_counts.iterrows():
        # Buscamos la regla usando la ubicación en mayúsculas para asegurar la coincidencia
        rule = get_rule_for_location(loc_info['location_upper'], rules_df)
        if rule is not None:
            if debug:
                print(f"  [DEBUG D4-Cap] Ubicación '{loc_info['location_upper']}': Conteo={loc_info['pallet_count']}, Capacidad={rule['capacity']}")
            if loc_info['pallet_count'] > rule['capacity']:
                pallets_in_loc = inventory_df[inventory_df['location'].str.upper() == loc_info['location_upper']]
                for _, pallet in pallets_in_loc.iterrows():
                    anomalies.append({
                        'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                        'anomaly_type': 'Ubicación con Sobre-capacidad', 'priority': 'MEDIA',
                        'details': f"La ubicación '{pallet['location']}' tiene {loc_info['pallet_count']} pallets pero su capacidad es {int(rule['capacity'])}."
                    })

    for index, pallet in inventory_df.iterrows():
        rule = get_rule_for_location(pallet['location'], rules_df)
        if rule is not None and isinstance(pallet['description'], str):
            # MEJORA: Comparamos todo en mayúsculas para ignorar el case.
            allowed_desc = rule['allowed_description'].upper()
            pallet_desc = pallet['description'].upper()
            if debug:
                 print(f"  [DEBUG D4-Incomp] Pallet '{pallet['pallet_id']}': Desc='{pallet_desc}', Regla='{allowed_desc}'")
            if not fnmatch.fnmatch(pallet_desc, allowed_desc):
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Incompatibilidad Producto-Ubicación', 'priority': 'BAJA',
                    'details': f"El producto '{pallet['description']}' no coincide con la regla de la ubicación ('{rule['allowed_description']}')."
                })
    return anomalies

def detect_unknown_locations(inventory_df, debug=False):
    """
    Detección 5: Encuentra pallets en ubicaciones no definidas en las reglas.
    """
    anomalies = []
    unknown_loc_pallets = inventory_df[inventory_df['location_type'] == 'UNKNOWN']
    
    if debug and not unknown_loc_pallets.empty:
        print("  [DEBUG D5] Pallets encontrados en ubicaciones desconocidas.")

    for index, pallet in unknown_loc_pallets.iterrows():
        anomalies.append({
            'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
            'anomaly_type': 'Ubicación Desconocida', 'priority': 'ALTA',
            'details': f"La ubicación '{pallet['location']}' no coincide con ninguna regla definida en warehouse_rules.xlsx."
        })
    return anomalies

def run_engine(inventory_df, rules_df, args):
    """
    Orquesta la ejecución de todas las funciones de detección y devuelve un
    reporte unificado y priorizado.
    """
    print("\n🚀 Ejecutando el motor de inteligencia de almacén...")
    
    # MEJORA: La lógica para asignar el tipo de ubicación ahora maneja 3 casos.
    def get_location_type(location, rules):
        if pd.isna(location) or not str(location).strip():
            return 'FALTANTE'
        rule = get_rule_for_location(location, rules)
        if rule is not None:
            return rule['location_type']
        return 'UNKNOWN'

    inventory_df['location_type'] = inventory_df['location'].apply(get_location_type, args=(rules_df,))
    
    all_anomalies = (
        detect_missing_locations(inventory_df, args.debug) + # <-- Nueva Detección 6
        detect_floating_pallets(inventory_df, args.floating_time, args.debug) +
        detect_lot_stragglers(inventory_df, rules_df, args.straggler_ratio, args.debug) +
        detect_stuck_in_transit_pallets(inventory_df, rules_df, args.stuck_ratio, args.stuck_time, args.debug) +
        detect_incompatibility_and_overcapacity(inventory_df, rules_df, args.debug) +
        detect_unknown_locations(inventory_df, args.debug)
    )
    
    # Eliminamos duplicados por si un pallet es detectado por varias razones
    unique_anomalies = []
    seen_anomalies = set()
    for anomaly in all_anomalies:
        # Creamos una tupla única para cada anomalía para poder detectarla
        anomaly_signature = (anomaly['pallet_id'], anomaly['anomaly_type'])
        if anomaly_signature not in seen_anomalies:
            unique_anomalies.append(anomaly)
            seen_anomalies.add(anomaly_signature)

    priority_map = {'MUY ALTA': 4, 'ALTA': 3, 'MEDIA': 2, 'BAJA': 1}
    unique_anomalies.sort(key=lambda x: priority_map.get(x['priority'], 0), reverse=True)
    
    print(f"✅ Motor finalizado. Se encontraron {len(unique_anomalies)} anomalías únicas.")
    return unique_anomalies

def display_report(anomalies):
    """
    Muestra el reporte final de anomalías de una forma clara y legible.
    """
    print("\n\n" + "="*50)
    print("🚨 REPORTE FINAL DE ANOMALÍAS (PRIORIZADO) �")
    print("="*50)
    
    if not anomalies:
        print("\n🎉 ¡No se encontraron anomalías! Todo en orden.\n")
        return
        
    for anomaly in anomalies:
        print(f"\n[ PRIORIDAD: {anomaly['priority']} ]")
        print(f"  - TIPO:      {anomaly['anomaly_type']}")
        print(f"  - PALLET:    {anomaly['pallet_id']}")
        print(f"  - UBICACIÓN: {anomaly['location']}")
        print(f"  - DETALLES:  {anomaly['details']}")
    
    print("\n" + "="*50)

def main():
    """
    Punto de entrada principal del script.
    """
    parser = argparse.ArgumentParser(description="Warehouse Intelligence Engine: Analiza reportes de inventario para encontrar anomalías.", formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('-i', '--inventory', default='data/inventory_report.xlsx', help='Ruta al archivo de inventario .xlsx. (Default: data/inventory_report.xlsx)')
    parser.add_argument('--debug', action='store_true', help='Activa el modo de depuración para ver detalles del procesamiento.')
    
    parser.add_argument('--straggler-ratio', type=float, default=0.85, help='Umbral de completitud de lote para detectar Rezagados (D2). Default: 0.85')
    parser.add_argument('--stuck-ratio', type=float, default=0.80, help='Umbral de completitud de lote para detectar Atascados (D3). Default: 0.80')
    parser.add_argument('--floating-time', type=int, default=8, help='Horas para considerar un pallet Flotante en recepción (D1). Default: 8')
    parser.add_argument('--stuck-time', type=int, default=6, help='Horas para considerar un pallet Atascado en tránsito (D3). Default: 6')

    args = parser.parse_args()

    print("Iniciando Warehouse Intelligence Engine...")
    
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    inventory_file = os.path.join(base_path, args.inventory)
    rules_file = os.path.join(base_path, 'data', 'warehouse_rules.xlsx')
    
    inventory_df, rules_df = load_data(inventory_file, rules_file)
    
    if inventory_df is None or rules_df is None:
        print("🛑 Ejecución detenida debido a errores en la carga de datos.")
        return

    final_anomalies = run_engine(inventory_df, rules_df, args)
    
    display_report(final_anomalies)


if __name__ == "__main__":
    main()
