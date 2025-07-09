# Ware-Intelligence Engine

A web application designed to analyze warehouse inventory reports and identify operational anomalies based on a defined set of business rules.

## Overview

The Ware-Intelligence Engine helps warehouse managers and operators improve efficiency by automatically detecting common issues in inventory management. By uploading an inventory spreadsheet, users can get a prioritized list of anomalies, such as misplaced pallets, stock that has been sitting for too long, or capacity violations. This allows teams to take targeted action to resolve inefficiencies in the warehouse.

The application is built with a simple, user-friendly interface that guides the user through a three-step process: uploading files, mapping data columns, and viewing the results.

## Features

-   **Upload Your Own Data**: Works with your existing inventory reports in Excel (`.xlsx`) format.
-   **Customizable Business Rules**: Define your warehouse layout, location capacities, and product storage rules in a simple Excel file. A default set of rules is provided.
-   **Intelligent Anomaly Detection**: The core engine runs a series of checks to find various types of issues.
-   **Prioritized Results**: Anomalies are categorized by priority (Very High, High, Medium, Low) so you can focus on what matters most.
-   **Column Mapping**: An intuitive interface allows you to map the columns from your report to the fields the engine needs.

## How It Works

The application operates in a simple three-step flow:

1.  **Upload Files**: On the main page, you upload your inventory report. You also have the option to upload a custom file of business rules; if you don't provide one, a default configuration will be used.
2.  **Map Columns**: You are then taken to a mapping screen where you match the column names from your spreadsheet (e.g., `Item Code`, `Timestamp`) to the standard fields the application expects (`pallet_id`, `creation_date`, etc.).
3.  **Get Results**: After mapping, the engine processes your data and displays a detailed report of all detected anomalies, sorted by priority.

## The Anomaly Engine

The engine is designed to detect several classes of common warehouse problems:

| Anomaly Type                          | Priority  | Description                                                                                                      |
| ------------------------------------- | :-------: | ---------------------------------------------------------------------------------------------------------------- |
| **Lot Straggler**                     | Very High | A pallet is still in the receiving area while the vast majority of its lot has already been stored.            |
| **Missing Location**                  | Very High | A pallet has no location assigned to it in the inventory report.                                                 |
| **Floating Pallet**                   |   High    | A pallet has remained in the "Receiving" dock for longer than the allowed time threshold.                        |
| **Unknown Location**                  |   High    | A pallet is registered in a location that does not exist in the defined warehouse rules.                         |
| **Stuck in Transit**                  |   High    | A pallet is stuck in a temporary transit location, either for too long or after its lot has been put away.       |
| **Overcapacity**                      |  Medium   | A storage location contains more pallets than its designated capacity allows.                                    |
| **Product-Location Incompatibility**  |    Low    | A product is stored in a location not designated for its type (e.g., a flammable item in a standard rack).     |


## How to Use

1.  Navigate to the application's homepage.
2.  Click "Choose File" to select your inventory report (`.xlsx`).
3.  (Optional) Click "Choose File" to select your warehouse rules file. If omitted, defaults will be used.
4.  Click "Upload".
5.  On the mapping page, use the dropdowns to match your file's columns to the required data fields.
6.  Click "Process Data".
7.  Review the prioritized list of anomalies on the results page.

## Technology Stack

-   **Backend**: Python, Flask
-   **Data Processing**: Pandas
-   **Frontend**: HTML, CSS (standard templates)
-   **Deployment**: Vercel