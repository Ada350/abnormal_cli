# Abnormal Security Monitoring Dashboard

This dashboard provides comprehensive monitoring of Abnormal Security email security incidents (threats and cases) with remediation capabilities.

## Features

- Real-time monitoring of security threats detected by Abnormal Security
- Detailed threat information display with attack type, severity, and remediation status
- Incident grading (P1-P4) based on severity and confidence
- Threat remediation actions including false positive reporting
- Filtering by time period and remediation status
- Direct links to Abnormal Security portal
- Multiple interface options: CLI and GUI with retro game-style menu

## Requirements

- Python 3.9+
- Abnormal Security API access token
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository
2. Set up a Python virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with your Abnormal Security API credentials:

```
ABNORMAL_API_TOKEN=your_api_token_here
ABNORMAL_API_URL=https://api.abnormalplatform.com
```

## Usage

### Quick Start (with virtual environment)

Use the provided shell script to automatically activate the virtual environment and run the tool:

```bash
./run_monitor.sh
```

This will start the retro game-style menu where you can choose between the CLI and GUI interfaces.

### Manual Start

If you prefer to start manually after activating your virtual environment:

For the interactive menu (choose between CLI and GUI):
```bash
python abnormal_monitor.py
```

For the GUI dashboard directly:
```bash
streamlit run incident_dashboard.py
```

The dashboard will be available at http://localhost:8501

## Dashboard Layout

- **Left Sidebar**: Configuration settings for incident type, time period, and status filters
- **Main Area**: 
  - Incident table showing all matching incidents
  - Detailed view of selected incident with metadata and security insights
  - Available remediation actions for the selected incident

## Project Structure

- `incident_dashboard.py`: Main Streamlit dashboard application
- `src/`: Source code directory
  - `abnormal_security_client.py`: Client for the Abnormal Security API
  - `incident_manager.py`: Business logic for incident handling and remediation
  - `ip_manager.py`: IP address management (for API whitelisting)
- `config/`: Configuration files
  - `settings.py`: Application settings and environment variable handling
- `exports/`: Directory for exported reports

## Development

To add new features or customize the dashboard:

1. Modify the appropriate component in the `src/` directory
2. Update the dashboard interface in `incident_dashboard.py`
3. Run the application to test your changes

## Testing

Run the test suite with:

```bash
python -m unittest discover
```

Or test specific components:

```bash
python test_abnormal_api.py
```

## License

This project is proprietary and not for redistribution.

## Support

For questions or issues, please contact your internal security team.
