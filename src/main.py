import pandas as pd
import os
import re
import fnmatch
import argparse 
from datetime import datetime, timedelta

def load_data(inventory_path, rules_path):
    """
    Loads data from inventory and rules Excel files.
    """
    try:
        inventory_df = pd.read_excel(inventory_path, parse_dates=['creation_date'])
        rules_df = pd.read_excel(rules_path)
        print(f"✅ Inventory file '{os.path.basename(inventory_path)}' loaded.")
        print(f"✅ Rules file '{os.path.basename(rules_path)}' loaded.")
        return inventory_df, rules_df
    except FileNotFoundError as e:
        print(f"❌ ERROR: File not found - {e}")
        return None, None
    except Exception as e:
        print(f"❌ ERROR: An unexpected error occurred while loading data - {e}")
        return None, None

def get_rule_for_location(location, rules_df):
    """
    Finds the business rule that corresponds to a specific location.
    Now it is case-insensitive.
    """
    if not isinstance(location, str): return None 
    location = location.strip()
    
    for index, rule in rules_df.iterrows():
        pattern = rule['location_pattern'].replace('*', '.*')
        # IMPROVEMENT: Added re.IGNORECASE to make the match case-insensitive.
        regex = f"^{pattern}$"
        if re.match(regex, location, re.IGNORECASE):
            return rule
    return None

# --- NEW DETECTION 6: MISSING LOCATION ---
def detect_missing_locations(inventory_df, debug=False):
    """
    Detection 6: Finds pallets with no assigned location.
    """
    anomalies = []
    # We filter to find pallets where the location type is 'MISSING'.
    missing_loc_pallets = inventory_df[inventory_df['location_type'] == 'MISSING']
    
    if debug and not missing_loc_pallets.empty:
        print("  [DEBUG D6] Pallets found with missing location.")

    for index, pallet in missing_loc_pallets.iterrows():
        anomalies.append({
            'pallet_id': pallet['pallet_id'], 'location': 'N/A',
            'anomaly_type': 'Missing Location', 'priority': 'VERY HIGH',
            'details': "The pallet has no location registered in the report."
        })
    return anomalies

def detect_floating_pallets(inventory_df, hours_threshold=8, debug=False):
    """
    Detection 1: Finds pallets in 'RECEIVING' for longer than allowed.
    """
    anomalies = []
    now = datetime.now()
    receiving_pallets = inventory_df[inventory_df['location'] == 'RECEIVING']
    for index, pallet in receiving_pallets.iterrows():
        time_in_receiving = now - pallet['creation_date']
        if debug:
            print(f"  [DEBUG D1] Pallet {pallet['pallet_id']} in RECEIVING for {time_in_receiving.total_seconds()/3600:.2f}h. Threshold: {hours_threshold}h.")
        if time_in_receiving > timedelta(hours=hours_threshold):
            anomalies.append({
                'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                'anomaly_type': 'Floating Pallet', 'priority': 'HIGH',
                'details': f"The pallet has been in RECEIVING for more than {hours_threshold} hours ({time_in_receiving.total_seconds()/3600:.2f}h)."
            })
    return anomalies

def detect_lot_stragglers(inventory_df, rules_df, completion_threshold=0.85, debug=False):
    """
    Detection 2: Finds straggler pallets from almost complete lots.
    """
    anomalies = []
    lots = inventory_df.groupby('receipt_number')
    for receipt_number, lot_df in lots:
        final_pallets = lot_df[lot_df['location_type'] == 'FINAL'].shape[0]
        total_pallets = lot_df.shape[0]
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D2] Lot '{receipt_number}': Ratio={completion_ratio:.2f}, Threshold={completion_threshold}")
        if completion_ratio >= completion_threshold:
            stragglers = lot_df[lot_df['location_type'] == 'RECEIVING']
            for index, pallet in stragglers.iterrows():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Lot Straggler', 'priority': 'VERY HIGH',
                    'details': f"{completion_ratio:.0%} of lot '{receipt_number}' has already been stored, but this pallet is still in reception."
                })
    return anomalies

def detect_stuck_in_transit_pallets(inventory_df, rules_df, lot_completion_threshold=0.80, hours_threshold=6, debug=False):
    """
    Detection 3: Finds pallets stuck in transit locations.
    """
    anomalies = []
    now = datetime.now()
    lots = inventory_df.groupby('receipt_number')
    for receipt_number, lot_df in lots:
        final_pallets = lot_df[lot_df['location_type'] == 'FINAL'].shape[0]
        total_pallets = lot_df.shape[0]
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D3-Lot] Lot '{receipt_number}': Ratio={completion_ratio:.2f}, Threshold={lot_completion_threshold}")
        if completion_ratio >= lot_completion_threshold:
            stuck_pallets = lot_df[lot_df['location_type'] == 'TRANSITIONAL']
            for index, pallet in stuck_pallets.iterrows():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Stuck in Transit (Full Lot)', 'priority': 'HIGH',
                    'details': f"{completion_ratio:.0%} of lot '{receipt_number}' has already been stored, but this pallet is still in a transit location."
                })
    transitional_pallets = inventory_df[inventory_df['location_type'] == 'TRANSITIONAL']
    for index, pallet in transitional_pallets.iterrows():
        time_in_transit = now - pallet['creation_date']
        if debug:
            print(f"  [DEBUG D3-Time] Pallet {pallet['pallet_id']} in Transit for {time_in_transit.total_seconds()/3600:.2f}h. Threshold: {hours_threshold}h.")
        if time_in_transit > timedelta(hours=hours_threshold):
            if not any(d['pallet_id'] == pallet['pallet_id'] for d in anomalies):
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Stuck in Transit (Time Exceeded)', 'priority': 'MEDIUM',
                    'details': f"The pallet has been in a transit location for more than {hours_threshold} hours ({time_in_transit.total_seconds()/3600:.2f}h)."
                })
    return anomalies

def detect_incompatibility_and_overcapacity(inventory_df, rules_df, debug=False):
    """
    Detection 4: Finds incompatible pallets and over-saturated locations.
    Now case-insensitive and robust to null data.
    """
    anomalies = []
    # We use a copy and ensure 'location' is of string type,
    # filling null values to avoid errors with .str.upper()
    temp_df = inventory_df.dropna(subset=['location']).copy()
    temp_df['location_upper'] = temp_df['location'].astype(str).str.upper()
    
    location_counts = temp_df['location_upper'].value_counts().reset_index()
    location_counts.columns = ['location_upper', 'pallet_count']
    
    for index, loc_info in location_counts.iterrows():
        # We search for the rule using the uppercase location to ensure a match
        rule = get_rule_for_location(loc_info['location_upper'], rules_df)
        if rule is not None:
            if debug:
                print(f"  [DEBUG D4-Cap] Location '{loc_info['location_upper']}': Count={loc_info['pallet_count']}, Capacity={rule['capacity']}")
            if loc_info['pallet_count'] > rule['capacity']:
                # We filter the original DataFrame using the same safe method
                pallets_in_loc = inventory_df[inventory_df['location'].astype(str).str.upper() == loc_info['location_upper']]
                for _, pallet in pallets_in_loc.iterrows():
                    anomalies.append({
                        'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                        'anomaly_type': 'Over-capacity Location', 'priority': 'MEDIUM',
                        'details': f"Location '{pallet['location']}' has {loc_info['pallet_count']} pallets but its capacity is {int(rule['capacity'])}."
                    })

    # We ensure that both 'location' and 'description' are not null for this check
    for index, pallet in inventory_df.dropna(subset=['location', 'description']).iterrows():
        rule = get_rule_for_location(pallet['location'], rules_df)
        if rule is not None:
            # We compare everything in uppercase to ignore case.
            # We use .astype(str) for safety, although dropna should have already handled it.
            allowed_desc = str(rule['allowed_description']).upper()
            pallet_desc = str(pallet['description']).upper()
            if debug:
                 print(f"  [DEBUG D4-Incomp] Pallet '{pallet['pallet_id']}': Desc='{pallet_desc}', Rule='{allowed_desc}'")
            if not fnmatch.fnmatch(pallet_desc, allowed_desc):
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Product-Location Incompatibility', 'priority': 'LOW',
                    'details': f"Product '{pallet['description']}' does not match the location's rule ('{rule['allowed_description']}')."
                })
    return anomalies

def detect_unknown_locations(inventory_df, debug=False):
    """
    Detection 5: Finds pallets in locations not defined in the rules.
    """
    anomalies = []
    unknown_loc_pallets = inventory_df[inventory_df['location_type'] == 'UNKNOWN']
    
    if debug and not unknown_loc_pallets.empty:
        print("  [DEBUG D5] Pallets found in unknown locations.")

    for index, pallet in unknown_loc_pallets.iterrows():
        anomalies.append({
            'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
            'anomaly_type': 'Unknown Location', 'priority': 'HIGH',
            'details': f"Location '{pallet['location']}' does not match any rule defined in warehouse_rules.xlsx."
        })
    return anomalies

def run_engine(inventory_df, rules_df, args):
    """
    Orchestrates the execution of all detection functions and returns a
    unified and prioritized report.
    """
    print("\n🚀 Running the warehouse intelligence engine...")
    
    # IMPROVEMENT: The logic to assign the location type now handles 3 cases.
    def get_location_type(location, rules):
        if pd.isna(location) or not str(location).strip():
            return 'MISSING'
        rule = get_rule_for_location(location, rules)
        if rule is not None:
            return rule['location_type']
        return 'UNKNOWN'

    inventory_df['location_type'] = inventory_df['location'].apply(get_location_type, args=(rules_df,))
    
    all_anomalies = (
        detect_missing_locations(inventory_df, args.debug) + # <-- New Detection 6
        detect_floating_pallets(inventory_df, args.floating_time, args.debug) +
        detect_lot_stragglers(inventory_df, rules_df, args.straggler_ratio, args.debug) +
        detect_stuck_in_transit_pallets(inventory_df, rules_df, args.stuck_ratio, args.stuck_time, args.debug) +
        detect_incompatibility_and_overcapacity(inventory_df, rules_df, args.debug) +
        detect_unknown_locations(inventory_df, args.debug)
    )
    
    # We remove duplicates in case a pallet is detected for multiple reasons
    unique_anomalies = []
    seen_anomalies = set()
    for anomaly in all_anomalies:
        # We create a unique tuple for each anomaly to detect it
        anomaly_signature = (anomaly['pallet_id'], anomaly['anomaly_type'])
        if anomaly_signature not in seen_anomalies:
            unique_anomalies.append(anomaly)
            seen_anomalies.add(anomaly_signature)

    priority_map = {'VERY HIGH': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    unique_anomalies.sort(key=lambda x: priority_map.get(x['priority'], 0), reverse=True)
    
    print(f"✅ Engine finished. Found {len(unique_anomalies)} unique anomalies.")
    return unique_anomalies

def summarize_anomalies_by_location(anomalies):
    """
    Transforms the list of anomalies into a strategic summary by location.
    """
    if not anomalies:
        return []

    anomalies_df = pd.DataFrame(anomalies)
    grouped = anomalies_df.groupby('location')
    
    summary_list = []
    priority_map = {'VERY HIGH': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    reverse_priority_map = {v: k for k, v in priority_map.items()}

    for location_name, group in grouped:
        anomaly_count = len(group)
        main_anomaly = group['anomaly_type'].mode()[0]
        
        # Map text priorities to numbers, find the max, and convert back to text
        highest_priority_num = group['priority'].apply(lambda p: priority_map[p]).max()
        highest_priority = reverse_priority_map[int(highest_priority_num)]
        
        summary_list.append({
            'location_name': location_name,
            'anomaly_count': anomaly_count,
            'main_anomaly': main_anomaly,
            'highest_priority': highest_priority
        })
        
    # Sort the summary by the number of anomalies in descending order
    summary_list.sort(key=lambda x: x['anomaly_count'], reverse=True)
    
    return summary_list

def display_report(anomalies):
    """
    Displays the final anomaly report in a clear and readable way.
    """
    print("\n\n" + "="*50)
    print("🚨 FINAL ANOMALY REPORT (PRIORITIZED) 🚨")
    print("="*50)
    
    if not anomalies:
        print("\n🎉 No anomalies found! Everything is in order.\n")
        return
        
    for anomaly in anomalies:
        print(f"\n[ PRIORITY: {anomaly['priority']} ]")
        print(f"  - TYPE:      {anomaly['anomaly_type']}")
        print(f"  - PALLET:    {anomaly['pallet_id']}")
        print(f"  - LOCATION: {anomaly['location']}")
        print(f"  - DETAILS:  {anomaly['details']}")
    
    print("\n" + "="*50)

def main():
    """
    Main entry point of the script.
    """
    parser = argparse.ArgumentParser(description="Warehouse Intelligence Engine: Analyzes inventory reports to find anomalies.", formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('-i', '--inventory', default='data/inventory_report.xlsx', help='Path to the inventory .xlsx file. (Default: data/inventory_report.xlsx)')
    parser.add_argument('--debug', action='store_true', help='Activates debug mode to see processing details.')
    
    parser.add_argument('--straggler-ratio', type=float, default=0.85, help='Lot completion threshold to detect Stragglers (D2). Default: 0.85')
    parser.add_argument('--stuck-ratio', type=float, default=0.80, help='Lot completion threshold to detect Stuck pallets (D3). Default: 0.80')
    parser.add_argument('--floating-time', type=int, default=8, help='Hours to consider a pallet as Floating in reception (D1). Default: 8')
    parser.add_argument('--stuck-time', type=int, default=6, help='Hours to consider a pallet as Stuck in transit (D3). Default: 6')

    args = parser.parse_args()

    print("Starting Warehouse Intelligence Engine...")
    
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    inventory_file = os.path.join(base_path, args.inventory)
    rules_file = os.path.join(base_path, 'data', 'warehouse_rules.xlsx')
    
    inventory_df, rules_df = load_data(inventory_file, rules_file)
    
    if inventory_df is None or rules_df is None:
        print("🛑 Execution stopped due to errors loading data.")
        return

    final_anomalies = run_engine(inventory_df, rules_df, args)
    
    display_report(final_anomalies)


if __name__ == "__main__":
    main()
