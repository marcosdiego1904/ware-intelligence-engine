import polars as pl
import os
import re
import fnmatch
import argparse
from datetime import datetime, timedelta

def load_data(inventory_path, rules_path):
    """
    Loads data from inventory and rules Excel files using Polars.
    """
    try:
        inventory_df = pl.read_excel(inventory_path)
        rules_df = pl.read_excel(rules_path)
        print(f"✅ Inventory file '{os.path.basename(inventory_path)}' loaded.")
        print(f"✅ Rules file '{os.path.basename(rules_path)}' loaded.")
        return inventory_df, rules_df
    except FileNotFoundError as e:
        print(f"❌ ERROR: File not found - {e}")
        return None, None
    except Exception as e:
        print(f"❌ ERROR: An unexpected error occurred while loading data - {e}")
        return None, None

def get_rule_for_location(location, rules_list):
    """
    Finds the business rule that corresponds to a specific location from a list of rules.
    Now it is case-insensitive.
    """
    if not isinstance(location, str): return None
    location = location.strip()

    for rule in rules_list:
        pattern = rule['location_pattern'].replace('*', '.*')
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
    missing_loc_pallets = inventory_df.filter(pl.col('location_type') == 'MISSING')
    
    if debug and len(missing_loc_pallets) > 0:
        print("  [DEBUG D6] Pallets found with missing location.")

    for pallet in missing_loc_pallets.to_dicts():
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
    receiving_pallets = inventory_df.filter(pl.col('location') == 'RECEIVING')
    for pallet in receiving_pallets.to_dicts():
        # Ensure creation_date is a datetime object before comparison
        creation_date = pallet['creation_date']
        if not isinstance(creation_date, datetime):
            # Attempt to parse if it's a string, though read_excel should handle it.
            # This is a safeguard.
            try:
                creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                continue # Skip if date is invalid

        time_in_receiving = now - creation_date
        if debug:
            print(f"  [DEBUG D1] Pallet {pallet['pallet_id']} in RECEIVING for {time_in_receiving.total_seconds()/3600:.2f}h. Threshold: {hours_threshold}h.")
        if time_in_receiving > timedelta(hours=hours_threshold):
            anomalies.append({
                'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                'anomaly_type': 'Floating Pallet', 'priority': 'HIGH',
                'details': f"The pallet has been in RECEIVING for more than {hours_threshold} hours ({time_in_receiving.total_seconds()/3600:.2f}h)."
            })
    return anomalies

def detect_lot_stragglers(inventory_df, rules_list, completion_threshold=0.85, debug=False):
    """
    Detection 2: Finds straggler pallets from almost complete lots.
    """
    anomalies = []
    # Polars' groupby is different; we iterate over groups.
    for receipt_number, lot_df in inventory_df.group_by('receipt_number'):
        final_pallets = lot_df.filter(pl.col('location_type') == 'FINAL').height
        total_pallets = lot_df.height
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D2] Lot '{receipt_number}': Ratio={completion_ratio:.2f}, Threshold={completion_threshold}")
        if completion_ratio >= completion_threshold:
            stragglers = lot_df.filter(pl.col('location_type') == 'RECEIVING')
            for pallet in stragglers.to_dicts():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Lot Straggler', 'priority': 'VERY HIGH',
                    'details': f"{completion_ratio:.0%} of lot '{receipt_number}' has already been stored, but this pallet is still in reception."
                })
    return anomalies

def detect_stuck_in_transit_pallets(inventory_df, rules_list, lot_completion_threshold=0.80, hours_threshold=6, debug=False):
    """
    Detection 3: Finds pallets stuck in transit locations.
    """
    anomalies = []
    now = datetime.now()
    # First part: check lots that are almost complete
    for receipt_number, lot_df in inventory_df.group_by('receipt_number'):
        final_pallets = lot_df.filter(pl.col('location_type') == 'FINAL').height
        total_pallets = lot_df.height
        completion_ratio = final_pallets / total_pallets if total_pallets > 0 else 0
        if debug:
            print(f"  [DEBUG D3-Lot] Lot '{receipt_number}': Ratio={completion_ratio:.2f}, Threshold={lot_completion_threshold}")
        if completion_ratio >= lot_completion_threshold:
            stuck_pallets = lot_df.filter(pl.col('location_type') == 'TRANSITIONAL')
            for pallet in stuck_pallets.to_dicts():
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Stuck in Transit (Full Lot)', 'priority': 'HIGH',
                    'details': f"{completion_ratio:.0%} of lot '{receipt_number}' has already been stored, but this pallet is still in a transit location."
                })
    
    # Second part: check any pallet in transit for too long
    transitional_pallets = inventory_df.filter(pl.col('location_type') == 'TRANSITIONAL')
    for pallet in transitional_pallets.to_dicts():
        creation_date = pallet['creation_date']
        if not isinstance(creation_date, datetime):
            try:
                creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                continue
        
        time_in_transit = now - creation_date
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

def detect_incompatibility_and_overcapacity(inventory_df, rules_list, debug=False):
    """
    Detection 4: Finds incompatible pallets and over-saturated locations.
    """
    anomalies = []
    # Drop rows with null locations and make a temporary uppercase column for matching
    temp_df = inventory_df.drop_nulls(subset=['location']).with_columns(
        pl.col('location').cast(pl.Utf8).str.to_uppercase().alias('location_upper')
    )

    location_counts = temp_df.group_by('location_upper').agg(pl.count().alias('pallet_count'))

    for loc_info in location_counts.to_dicts():
        rule = get_rule_for_location(loc_info['location_upper'], rules_list)
        if rule is not None:
            capacity = rule.get('capacity', float('inf')) # Safely get capacity
            if debug:
                print(f"  [DEBUG D4-Cap] Location '{loc_info['location_upper']}': Count={loc_info['pallet_count']}, Capacity={capacity}")
            if loc_info['pallet_count'] > capacity:
                pallets_in_loc = inventory_df.filter(pl.col('location').str.to_uppercase() == loc_info['location_upper'])
                for pallet in pallets_in_loc.to_dicts():
                    anomalies.append({
                        'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                        'anomaly_type': 'Over-capacity Location', 'priority': 'MEDIUM',
                        'details': f"Location '{pallet['location']}' has {loc_info['pallet_count']} pallets but its capacity is {int(capacity)}."
                    })

    # Incompatibility check
    for pallet in inventory_df.drop_nulls(subset=['location', 'description']).to_dicts():
        rule = get_rule_for_location(pallet['location'], rules_list)
        if rule is not None:
            allowed_desc = str(rule.get('allowed_description', '')).upper()
            pallet_desc = str(pallet.get('description', '')).upper()
            if debug:
                 print(f"  [DEBUG D4-Incomp] Pallet '{pallet['pallet_id']}': Desc='{pallet_desc}', Rule='{allowed_desc}'")
            if not fnmatch.fnmatch(pallet_desc, allowed_desc):
                anomalies.append({
                    'pallet_id': pallet['pallet_id'], 'location': pallet['location'],
                    'anomaly_type': 'Product-Location Incompatibility', 'priority': 'LOW',
                    'details': f"Product '{pallet['description']}' does not match the location's rule ('{rule.get('allowed_description', 'N/A')}')."
                })
    return anomalies

def detect_unknown_locations(inventory_df, debug=False):
    """
    Detection 5: Finds pallets in locations not defined in the rules.
    """
    anomalies = []
    unknown_loc_pallets = inventory_df.filter(pl.col('location_type') == 'UNKNOWN')
    
    if debug and len(unknown_loc_pallets) > 0:
        print("  [DEBUG D5] Pallets found in unknown locations.")

    for pallet in unknown_loc_pallets.to_dicts():
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
    
    # Convert rules to a list of dicts for easier iteration in helper functions
    rules_list = rules_df.to_dicts()

    def get_location_type(location):
        # The function now takes a single location string and uses the pre-converted list
        if location is None or not str(location).strip():
            return 'MISSING'
        rule = get_rule_for_location(location, rules_list)
        if rule is not None:
            return rule['location_type']
        return 'UNKNOWN'

    # Use .map_elements() for applying the custom Python function
    inventory_df = inventory_df.with_columns(
        pl.col('location').map_elements(get_location_type, return_dtype=pl.Utf8).alias('location_type')
    )
    
    all_anomalies = (
        detect_missing_locations(inventory_df, args.debug) +
        detect_floating_pallets(inventory_df, args.floating_time, args.debug) +
        detect_lot_stragglers(inventory_df, rules_list, args.straggler_ratio, args.debug) +
        detect_stuck_in_transit_pallets(inventory_df, rules_list, args.stuck_ratio, args.stuck_time, args.debug) +
        detect_incompatibility_and_overcapacity(inventory_df, rules_list, args.debug) +
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
    Transforms the list of anomalies into a strategic summary by location using Polars.
    """
    if not anomalies:
        return pl.DataFrame()
    
    # Convert list of dicts to a Polars DataFrame
    anomalies_df = pl.DataFrame(anomalies)
    
    # Create the summary using Polars group_by and aggregation
    summary = anomalies_df.group_by('location').agg(
        pl.count().alias('total_anomalies'),
        pl.col('pallet_id').n_unique().alias('unique_pallets_affected'),
        pl.col('anomaly_type').unique().alias('anomaly_types')
    ).sort('total_anomalies', descending=True)
    
    return summary

def display_report(anomalies, summary_df):
    """
    Displays the detailed report of anomalies and the summary by location.
    """
    print("\n--- 🚨 Detailed Anomaly Report ---")
    if anomalies:
        # We can create a DataFrame just for display purposes if needed
        display_df = pl.DataFrame(anomalies)
        print(display_df)
    else:
        print("✅ No anomalies detected. The warehouse is in perfect condition!")

    print("\n--- 📈 Strategic Summary by Location ---")
    if not summary_df.is_empty():
        print(summary_df)
    else:
        print("✅ No summary to display.")

def main():
    """
    Main function to execute the script.
    """
    parser = argparse.ArgumentParser(description="Warehouse Intelligence Engine")
    parser.add_argument('inventory_file', type=str, help="Path to the inventory Excel file.")
    parser.add_argument('--rules', type=str, default='warehouse_rules.xlsx', help="Path to the business rules Excel file.")
    # Detection 1: Floating Pallets
    parser.add_argument('--floating-time', type=int, default=8, help="Hours a pallet can be in 'RECEIVING'.")
    # Detection 2: Lot Stragglers
    parser.add_argument('--straggler-ratio', type=float, default=0.85, help="Completion ratio to detect lot stragglers.")
    # Detection 3: Stuck in Transit
    parser.add_argument('--stuck-ratio', type=float, default=0.80, help="Lot completion ratio to consider transit pallets stuck.")
    parser.add_argument('--stuck-time', type=int, default=6, help="Hours a pallet can be in a transit location.")
    # General
    parser.add_argument('--debug', action='store_true', help="Enable debug prints.")
    
    args = parser.parse_args()

    inventory_df, rules_df = load_data(args.inventory_file, args.rules)

    if inventory_df is not None and rules_df is not None:
        anomalies = run_engine(inventory_df, rules_df, args)
        summary = summarize_anomalies_by_location(anomalies)
        display_report(anomalies, summary)

if __name__ == "__main__":
    main()
