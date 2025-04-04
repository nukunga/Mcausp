# server.py
import psutil
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("security_scanner")

try:
    import winreg  # Windows-specific module
except ImportError:
    winreg = None
    logger.warning("winreg module not available")

try:
    import wmi  # Windows Management Instrumentation
except ImportError:
    wmi = None
    logger.warning("wmi module not available")

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.prompts import Prompt
except ImportError as e:
    logger.error(f"Failed to import FastMCP: {e}")
    print(f"Error: FastMCP module could not be imported. Please make sure it's installed correctly.")
    sys.exit(1)

from security_tools import (
    scan_policies, 
    check_registry_and_firewall, 
    analyze_processes, 
    check_security_events,
    scan_security,
    evaluate_vulnerabilities
)
from prompt_templates import analyze_security_status, analyze_specific_area

# Create MCP server (with minimal dependencies)
logger.info("Initializing Windows Security Scanner")
try:
    mcp = FastMCP("Windows Security Scanner")
    
    # Register tools with proper error handling
    logger.info("Registering tools...")
    tools = [
        scan_policies, 
        check_registry_and_firewall, 
        analyze_processes, 
        check_security_events,
        scan_security,
        evaluate_vulnerabilities
    ]
    
    for tool in tools:
        try:
            mcp.add_tool(tool)
            logger.info(f"Added tool: {tool.__name__}")
        except Exception as e:
            logger.error(f"Failed to add tool {tool.__name__}: {e}")
    
    # Create and register prompts
    logger.info("Registering prompts...")
    try:
        security_status_prompt = Prompt(
            name="analyze_security_status",
            description="Analyze the security status of the Windows system",
            template=analyze_security_status(),
            fn=analyze_security_status
        )
        mcp.add_prompt(security_status_prompt)
        logger.info("Added security status prompt")
    except Exception as e:
        logger.error(f"Failed to register security status prompt: {e}")
    
    try:
        specific_area_prompt = Prompt(
            name="analyze_specific_area",
            description="Deep analysis of a specific security area",
            template=analyze_specific_area("process_anomalies"),
            fn=analyze_specific_area,
            parameters=[
                {
                    "name": "area",
                    "description": "Security area to analyze (policies, registry_and_firewall, process_anomalies, security_events)",
                    "type": "string",
                    "required": True
                }
            ]
        )
        mcp.add_prompt(specific_area_prompt)
        logger.info("Added specific area prompt")
    except Exception as e:
        logger.error(f"Failed to register specific area prompt: {e}")
    
    # Run MCP server
    if __name__ == "__main__":
        print("Starting Windows Security Scanner. Press Ctrl+C to exit.")
        try:
            logger.info("Starting FastMCP server")
            mcp.run()
        except KeyboardInterrupt:
            # Just log this event, don't try to print
            logger.info("Server stopped by user")
        except Exception as e:
            # Log the error but don't try to print it
            logger.error(f"Server error: {str(e)}")
except Exception as e:
    logger.error(f"Initialization error: {e}")
    print(f"Failed to initialize Windows Security Scanner: {e}")
    sys.exit(1)
