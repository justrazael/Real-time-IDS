"""
IDS Export & Reporting Module
Supports CSV, JSON, and Excel exports with filtering capabilities
Compatible with Real-time Intrusion Detection System
"""

import pandas as pd
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IDSExporter:
    """
    Export and reporting functionality for IDS detection results
    Works with flow_df DataFrame from application.py
    """
    
    def __init__(self, output_dir: str = "exports"):
        """
        Initialize the exporter
        
        Args:
            output_dir: Directory to save exported files
        """
        self.output_dir = output_dir
        self._create_output_directory()
        
        # Define severity levels mapping based on application.py risk calculations
        self.severity_mapping = {
            "Very High": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Minimal": 1
        }
        
        # Classification types from CICIDS 2018 dataset
        self.attack_types = [
            'Benign', 'Botnet', 'DDoS', 'DoS', 
            'FTP-Patator', 'Probe', 'SSH-Patator', 'Web Attack'
        ]
    
    def _create_output_directory(self):
        """Create output directory if it doesn't exist"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logger.info(f"Created output directory: {self.output_dir}")
    
    def _generate_filename(self, prefix: str, extension: str) -> str:
        """
        Generate timestamped filename
        
        Args:
            prefix: Filename prefix (e.g., 'ids_report')
            extension: File extension without dot (e.g., 'csv')
        
        Returns:
            Full filepath with timestamp
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp}.{extension}"
        return os.path.join(self.output_dir, filename)
    
    def _parse_risk_level(self, risk_html: str) -> str:
        """
        Extract risk level from HTML string (from application.py Risk column)
        
        Args:
            risk_html: HTML string containing risk level like '<p style="color:red;">Very High</p>'
        
        Returns:
            Risk level as string
        """
        if not isinstance(risk_html, str):
            return "Unknown"
            
        # Remove HTML tags and extract text
        clean_text = re.sub(r'<[^>]+>', '', risk_html).strip()
        
        if "Very High" in clean_text:
            return "Very High"
        elif "High" in clean_text:
            return "High"
        elif "Medium" in clean_text:
            return "Medium"
        elif "Low" in clean_text:
            return "Low"
        elif "Minimal" in clean_text:
            return "Minimal"
        return "Unknown"
    
    def _clean_ip_string(self, ip_str: str) -> str:
        """
        Clean IP string by removing HTML img tags (from application.py classify function)
        
        Args:
            ip_str: IP string possibly containing HTML img tags
        
        Returns:
            Clean IP address string
        """
        if not isinstance(ip_str, str):
            return str(ip_str)
        
        # Remove HTML img tags
        clean_ip = re.sub(r'<img[^>]*>', '', ip_str).strip()
        return clean_ip
    
    def filter_data(
        self,
        df: pd.DataFrame,
        severity_levels: Optional[List[str]] = None,
        classifications: Optional[List[str]] = None,
        src_ips: Optional[List[str]] = None,
        dest_ips: Optional[List[str]] = None,
        protocols: Optional[List[str]] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        min_probability: Optional[float] = None
    ) -> pd.DataFrame:
        """
        Filter dataframe based on various criteria
        
        Args:
            df: Input dataframe (flow_df from application.py)
            severity_levels: List of severity levels to include (e.g., ['High', 'Very High'])
            classifications: List of attack classifications (e.g., ['DDoS', 'Botnet'])
            src_ips: List of source IPs to filter
            dest_ips: List of destination IPs to filter
            protocols: List of protocols to filter (e.g., ['TCP', 'UDP'])
            date_from: Start date for filtering (format: 'YYYY-MM-DD HH:MM:SS')
            date_to: End date for filtering (format: 'YYYY-MM-DD HH:MM:SS')
            min_probability: Minimum probability threshold (0.0 to 1.0)
        
        Returns:
            Filtered dataframe
        """
        if df.empty:
            logger.warning("Input dataframe is empty")
            return df
        
        filtered_df = df.copy()
        
        # Parse risk levels from HTML if Risk column exists
        if 'Risk' in filtered_df.columns:
            filtered_df['RiskLevel'] = filtered_df['Risk'].apply(self._parse_risk_level)
            
            # Filter by severity levels
            if severity_levels:
                filtered_df = filtered_df[filtered_df['RiskLevel'].isin(severity_levels)]
                logger.info(f"Filtered by severity levels: {severity_levels} - {len(filtered_df)} records remain")
        
        # Filter by classifications
        if classifications and 'Classification' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['Classification'].isin(classifications)]
            logger.info(f"Filtered by classifications: {classifications} - {len(filtered_df)} records remain")
        
        # Clean and filter by source IPs
        if src_ips and 'Src' in filtered_df.columns:
            # Clean IP strings from HTML
            filtered_df['CleanSrc'] = filtered_df['Src'].apply(self._clean_ip_string)
            filtered_df = filtered_df[filtered_df['CleanSrc'].isin(src_ips)]
            filtered_df = filtered_df.drop(columns=['CleanSrc'])
            logger.info(f"Filtered by source IPs: {len(src_ips)} IPs - {len(filtered_df)} records remain")
        
        # Clean and filter by destination IPs
        if dest_ips and 'Dest' in filtered_df.columns:
            # Clean IP strings from HTML
            filtered_df['CleanDest'] = filtered_df['Dest'].apply(self._clean_ip_string)
            filtered_df = filtered_df[filtered_df['CleanDest'].isin(dest_ips)]
            filtered_df = filtered_df.drop(columns=['CleanDest'])
            logger.info(f"Filtered by destination IPs: {len(dest_ips)} IPs - {len(filtered_df)} records remain")
        
        # Filter by protocols
        if protocols and 'Protocol' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['Protocol'].isin(protocols)]
            logger.info(f"Filtered by protocols: {protocols} - {len(filtered_df)} records remain")
        
        # Filter by date range
        if date_from and 'FlowStartTime' in filtered_df.columns:
            try:
                filtered_df['FlowStartTime'] = pd.to_datetime(filtered_df['FlowStartTime'])
                filtered_df = filtered_df[filtered_df['FlowStartTime'] >= pd.to_datetime(date_from)]
                logger.info(f"Filtered by start date: {date_from} - {len(filtered_df)} records remain")
            except Exception as e:
                logger.error(f"Error filtering by start date: {e}")
        
        if date_to and 'FlowLastSeen' in filtered_df.columns:
            try:
                filtered_df['FlowLastSeen'] = pd.to_datetime(filtered_df['FlowLastSeen'])
                filtered_df = filtered_df[filtered_df['FlowLastSeen'] <= pd.to_datetime(date_to)]
                logger.info(f"Filtered by end date: {date_to} - {len(filtered_df)} records remain")
            except Exception as e:
                logger.error(f"Error filtering by end date: {e}")
        
        # Filter by minimum probability
        if min_probability is not None and 'Probability' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['Probability'] >= min_probability]
            logger.info(f"Filtered by minimum probability: {min_probability} - {len(filtered_df)} records remain")
        
        logger.info(f"Final filtered data: {len(filtered_df)} records from {len(df)} total")
        return filtered_df
    
    def _prepare_export_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Prepare dataframe for export by cleaning HTML and formatting
        
        Args:
            df: Input dataframe
        
        Returns:
            Cleaned dataframe ready for export
        """
        export_df = df.copy()
        
        # Clean IP addresses from HTML
        if 'Src' in export_df.columns:
            export_df['Src'] = export_df['Src'].apply(self._clean_ip_string)
        
        if 'Dest' in export_df.columns:
            export_df['Dest'] = export_df['Dest'].apply(self._clean_ip_string)
        
        # Clean Risk HTML
        if 'Risk' in export_df.columns:
            export_df['Risk'] = export_df['Risk'].apply(self._parse_risk_level)
        
        return export_df
    
    def export_to_csv(
        self,
        df: pd.DataFrame,
        filename_prefix: str = "ids_report",
        include_columns: Optional[List[str]] = None
    ) -> str:
        """
        Export data to CSV format
        
        Args:
            df: Dataframe to export (flow_df from application.py)
            filename_prefix: Prefix for the output filename
            include_columns: Specific columns to include (None = all columns)
        
        Returns:
            Path to the exported file
        """
        try:
            if df.empty:
                logger.warning("Cannot export empty dataframe")
                return None
            
            # Prepare dataframe for export
            export_df = self._prepare_export_df(df)
            
            # Select columns if specified
            if include_columns:
                available_cols = [col for col in include_columns if col in export_df.columns]
                export_df = export_df[available_cols]
            
            # Generate filename
            filepath = self._generate_filename(filename_prefix, "csv")
            
            # Export to CSV
            export_df.to_csv(filepath, index=False, encoding='utf-8')
            logger.info(f"CSV export successful: {filepath}")
            logger.info(f"Exported {len(export_df)} records with {len(export_df.columns)} columns")
            
            return filepath
        
        except Exception as e:
            logger.error(f"CSV export failed: {str(e)}")
            raise
    
    def export_to_json(
        self,
        df: pd.DataFrame,
        filename_prefix: str = "ids_report",
        pretty_print: bool = True
    ) -> str:
        """
        Export data to JSON format
        
        Args:
            df: Dataframe to export (flow_df from application.py)
            filename_prefix: Prefix for the output filename
            pretty_print: Whether to format JSON with indentation
        
        Returns:
            Path to the exported file
        """
        try:
            if df.empty:
                logger.warning("Cannot export empty dataframe")
                return None
            
            # Prepare dataframe for export
            export_df = self._prepare_export_df(df)
            
            # Generate filename
            filepath = self._generate_filename(filename_prefix, "json")
            
            # Convert dataframe to JSON
            json_data = export_df.to_dict(orient='records')
            
            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                if pretty_print:
                    json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
                else:
                    json.dump(json_data, f, ensure_ascii=False, default=str)
            
            logger.info(f"JSON export successful: {filepath}")
            logger.info(f"Exported {len(export_df)} records")
            
            return filepath
        
        except Exception as e:
            logger.error(f"JSON export failed: {str(e)}")
            raise
    
    def export_to_excel(
        self,
        df: pd.DataFrame,
        filename_prefix: str = "ids_report",
        sheet_name: str = "IDS_Detections",
        include_summary: bool = True
    ) -> str:
        """
        Export data to Excel format with optional summary sheet
        
        Args:
            df: Dataframe to export (flow_df from application.py)
            filename_prefix: Prefix for the output filename
            sheet_name: Name of the main data sheet
            include_summary: Whether to include a summary statistics sheet
        
        Returns:
            Path to the exported file
        """
        try:
            if df.empty:
                logger.warning("Cannot export empty dataframe")
                return None
            
            # Prepare dataframe for export
            export_df = self._prepare_export_df(df)
            
            # Generate filename
            filepath = self._generate_filename(filename_prefix, "xlsx")
            
            # Create Excel writer
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                # Write main data
                export_df.to_excel(writer, sheet_name=sheet_name, index=False)
                
                # Add summary sheet if requested
                if include_summary:
                    summary_df = self._generate_summary_statistics(df)
                    summary_df.to_excel(writer, sheet_name='Summary')
            
            logger.info(f"Excel export successful: {filepath}")
            logger.info(f"Exported {len(export_df)} records")
            
            return filepath
        
        except Exception as e:
            logger.error(f"Excel export failed: {str(e)}")
            logger.error("Make sure 'openpyxl' is installed: pip install openpyxl")
            raise
    
    def _generate_summary_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate summary statistics for the report
        Compatible with flow_df structure from application.py
        
        Args:
            df: Input dataframe
        
        Returns:
            Summary dataframe
        """
        summary = {}
        
        # Total flows
        summary['Total Flows'] = len(df)
        
        # Classification breakdown
        if 'Classification' in df.columns:
            classification_counts = df['Classification'].value_counts()
            for classification, count in classification_counts.items():
                summary[f'Classification: {classification}'] = count
            
            # Calculate attack percentage
            malicious = len(df[df['Classification'] != 'Benign'])
            benign = len(df[df['Classification'] == 'Benign'])
            summary['Malicious Flows'] = malicious
            summary['Benign Flows'] = benign
            if len(df) > 0:
                summary['Attack Percentage'] = f"{(malicious / len(df) * 100):.2f}%"
        
        # Risk level breakdown
        if 'Risk' in df.columns:
            df_copy = df.copy()
            df_copy['RiskLevel'] = df_copy['Risk'].apply(self._parse_risk_level)
            risk_counts = df_copy['RiskLevel'].value_counts()
            for risk, count in risk_counts.items():
                summary[f'Risk Level: {risk}'] = count
        
        # Protocol breakdown
        if 'Protocol' in df.columns:
            protocol_counts = df['Protocol'].value_counts()
            for protocol, count in protocol_counts.items():
                summary[f'Protocol: {protocol}'] = count
        
        # Top source IPs (cleaned)
        if 'Src' in df.columns:
            df_copy = df.copy()
            df_copy['CleanSrc'] = df_copy['Src'].apply(self._clean_ip_string)
            top_src = df_copy['CleanSrc'].value_counts().head(5)
            for i, (ip, count) in enumerate(top_src.items(), 1):
                summary[f'Top Source IP #{i}'] = f"{ip} ({count} flows)"
        
        # Top destination IPs (cleaned)
        if 'Dest' in df.columns:
            df_copy = df.copy()
            df_copy['CleanDest'] = df_copy['Dest'].apply(self._clean_ip_string)
            top_dest = df_copy['CleanDest'].value_counts().head(5)
            for i, (ip, count) in enumerate(top_dest.items(), 1):
                summary[f'Top Destination IP #{i}'] = f"{ip} ({count} flows)"
        
        # Average probability
        if 'Probability' in df.columns:
            summary['Average Probability'] = f"{df['Probability'].mean():.4f}"
            summary['Max Probability'] = f"{df['Probability'].max():.4f}"
            summary['Min Probability'] = f"{df['Probability'].min():.4f}"
        
        # Port statistics
        if 'DestPort' in df.columns:
            top_ports = df['DestPort'].value_counts().head(5)
            for i, (port, count) in enumerate(top_ports.items(), 1):
                summary[f'Top Destination Port #{i}'] = f"{port} ({count} flows)"
        
        # Create summary dataframe
        summary_df = pd.DataFrame.from_dict(summary, orient='index', columns=['Value'])
        return summary_df
    
    def export_with_filters(
        self,
        df: pd.DataFrame,
        export_format: str = "csv",
        filename_prefix: str = "ids_filtered_report",
        **filter_kwargs
    ) -> str:
        """
        Export data with filters applied
        
        Args:
            df: Input dataframe (flow_df from application.py)
            export_format: Output format ('csv', 'json', or 'excel')
            filename_prefix: Prefix for the output filename
            **filter_kwargs: Filtering parameters (passed to filter_data)
        
        Returns:
            Path to the exported file or None if no data matches
        """
        # Apply filters
        filtered_df = self.filter_data(df, **filter_kwargs)
        
        if len(filtered_df) == 0:
            logger.warning("No data matches the specified filters!")
            return None
        
        # Export based on format
        export_format = export_format.lower()
        if export_format == 'csv':
            return self.export_to_csv(filtered_df, filename_prefix)
        elif export_format == 'json':
            return self.export_to_json(filtered_df, filename_prefix)
        elif export_format == 'excel':
            return self.export_to_excel(filtered_df, filename_prefix)
        else:
            raise ValueError(f"Unsupported export format: {export_format}. Use 'csv', 'json', or 'excel'")
    
    def generate_security_report(
        self,
        df: pd.DataFrame,
        report_title: str = "IDS Security Report"
    ) -> Dict:
        """
        Generate comprehensive security report with statistics
        Compatible with flow_df from application.py
        
        Args:
            df: Input dataframe (flow_df from application.py)
            report_title: Title for the report
        
        Returns:
            Dictionary containing report data
        """
        report = {
            'title': report_title,
            'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_flows': len(df),
            'statistics': {}
        }
        
        if df.empty:
            report['statistics']['message'] = 'No data available'
            return report
        
        # Classification statistics
        if 'Classification' in df.columns:
            report['statistics']['classifications'] = df['Classification'].value_counts().to_dict()
            
            # Attack statistics
            malicious = df[df['Classification'] != 'Benign']
            report['statistics']['malicious_flows'] = len(malicious)
            report['statistics']['benign_flows'] = len(df) - len(malicious)
            report['statistics']['attack_percentage'] = round(
                len(malicious) / len(df) * 100, 2
            ) if len(df) > 0 else 0
        
        # Risk level statistics
        if 'Risk' in df.columns:
            df_copy = df.copy()
            df_copy['RiskLevel'] = df_copy['Risk'].apply(self._parse_risk_level)
            report['statistics']['risk_levels'] = df_copy['RiskLevel'].value_counts().to_dict()
        
        # Top attackers (cleaned IPs)
        if 'Src' in df.columns and 'Classification' in df.columns:
            attackers_df = df[df['Classification'] != 'Benign'].copy()
            if not attackers_df.empty:
                attackers_df['CleanSrc'] = attackers_df['Src'].apply(self._clean_ip_string)
                attackers = attackers_df['CleanSrc'].value_counts().head(10)
                report['statistics']['top_attackers'] = attackers.to_dict()
        
        # Top targets (cleaned IPs)
        if 'Dest' in df.columns and 'Classification' in df.columns:
            targets_df = df[df['Classification'] != 'Benign'].copy()
            if not targets_df.empty:
                targets_df['CleanDest'] = targets_df['Dest'].apply(self._clean_ip_string)
                targets = targets_df['CleanDest'].value_counts().head(10)
                report['statistics']['top_targets'] = targets.to_dict()
        
        # Protocol distribution
        if 'Protocol' in df.columns:
            report['statistics']['protocols'] = df['Protocol'].value_counts().to_dict()
        
        # Port statistics
        if 'DestPort' in df.columns:
            top_ports = df['DestPort'].value_counts().head(10)
            report['statistics']['top_destination_ports'] = top_ports.to_dict()
        
        # Probability statistics
        if 'Probability' in df.columns:
            report['statistics']['probability'] = {
                'mean': round(df['Probability'].mean(), 4),
                'max': round(df['Probability'].max(), 4),
                'min': round(df['Probability'].min(), 4)
            }
        
        return report


# Utility functions for integration with application.py

def export_high_severity_alerts(flow_df: pd.DataFrame, output_dir: str = 'exports') -> str:
    """
    Quick function to export only high and very high severity alerts
    
    Args:
        flow_df: Flow dataframe from application.py
        output_dir: Directory to save exports
    
    Returns:
        Path to exported file
    """
    exporter = IDSExporter(output_dir=output_dir)
    return exporter.export_with_filters(
        flow_df,
        export_format='csv',
        filename_prefix='high_severity_alerts',
        severity_levels=['High', 'Very High']
    )


def export_attack_summary(flow_df: pd.DataFrame, output_dir: str = 'exports') -> str:
    """
    Quick function to export non-benign traffic summary
    
    Args:
        flow_df: Flow dataframe from application.py
        output_dir: Directory to save exports
    
    Returns:
        Path to exported file
    """
    exporter = IDSExporter(output_dir=output_dir)
    
    # Filter out benign traffic
    attack_types = ['Botnet', 'DDoS', 'DoS', 'FTP-Patator', 'Probe', 'SSH-Patator', 'Web Attack']
    
    return exporter.export_with_filters(
        flow_df,
        export_format='excel',
        filename_prefix='attack_summary',
        classifications=attack_types
    )


if __name__ == "__main__":
    # Example usage
    print("="*60)
    print("IDS Export & Reporting Module")
    print("="*60)
    print("\nThis module provides export and reporting capabilities")
    print("for the Real-time Intrusion Detection System.")
    print("\nFeatures:")
    print("  ✓ Export to CSV, JSON, and Excel formats")
    print("  ✓ Advanced filtering (severity, classification, IPs, dates)")
    print("  ✓ Automatic summary statistics")
    print("  ✓ Security report generation")
    print("  ✓ Compatible with flow_df from application.py")
    print("\nUsage in application.py:")
    print("  from export_reports import IDSExporter")
    print("  exporter = IDSExporter(output_dir='exports')")
    print("  exporter.export_to_csv(flow_df, 'my_report')")
    print("="*60)