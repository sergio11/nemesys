from nemesys.utils.logger import nemesysLogger
from langchain_groq import ChatGroq
from langchain.text_splitter import CharacterTextSplitter
from langchain_huggingface.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from fpdf import FPDF
import json


class SecurityAnalyzer:
    """
    A class responsible for analyzing system enumeration data and generating detailed security reports
    using a Retrieval-Augmented Generation (RAG) approach powered by an AI model. The reports include
    key security insights based on the system log file provided and are saved in PDF and JSON formats.
    
    Attributes:
        model (ChatGroq): The AI model used for generating the report.
    """

    def __init__(self, model_id="llama3-70b-8192", groq_api_key=None):
        """
        Initializes the SecurityAnalyzer instance with the specified model and Groq API key.

        Args:
            model_id (str): The ID of the model to be used (default is "llama3-70b-8192").
            groq_api_key (str): The API key for authenticating with the Groq API.

        Raises:
            ValueError: If no Groq API key is provided.
        """
        if not groq_api_key:
            nemesysLogger.error("💥 Groq API key is required! ⚠️")
            raise ValueError("Groq API key is required.")
        
        # Initialize the ChatGroq model
        self.model = ChatGroq(model=model_id, temperature=0, api_key=groq_api_key)

        nemesysLogger.info("🚀 Initialized Groq model successfully.")

    def generate_report(self, log_file_path="system_enumeration.log", pdf_path="nemesys_report.pdf", json_path="nemesys_report.json"):
        """
        Generates a comprehensive security report based on the given system enumeration log file. The report
        includes security insights, recommendations, and anomalies, and is saved in both PDF and JSON formats.

        Args:
            log_file_path (str): The path to the system enumeration log file to analyze (default is "system_enumeration.log").
            pdf_path (str): The path to save the generated PDF report (default is "nemesys_report.pdf").
            json_path (str): The path to save the generated JSON report (default is "nemesys_report.json").

        Returns:
            str: A message indicating the completion of the report generation or an error message if something fails.
        """
        try:
            # Preprocess the log file by splitting it into manageable chunks
            nemesysLogger.info("🛠️ Splitting log file into chunks for analysis...")
            self.chunks = self._split_log_into_chunks(log_file_path)
            
            # Set up the FAISS index for RAG with HuggingFace embeddings
            nemesysLogger.info("🔍 Setting up FAISS index for document retrieval...")
            self.embeddings = HuggingFaceEmbeddings()
            self.vector_store = FAISS.from_documents(self.chunks, self.embeddings)
            
            # Create the retrieval chain
            retriever = self.vector_store.as_retriever()
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)
            
            # Define the prompt for generating the security report
            prompt = self._create_report_prompt()

            # Run the analysis using the retrieval chain
            nemesysLogger.info("⚡ Running security analysis using the AI model...")
            analysis = chain.invoke(prompt)

            nemesysLogger.info("📝 Generating PDF and JSON reports based on the analysis...")
            # Generate the PDF and JSON reports based on the analysis
            self._generate_pdf_report(analysis, pdf_path)
            self._generate_json_report(analysis, json_path)

            nemesysLogger.info("✅ Report generation complete. PDF and JSON reports have been saved.")
            return "Report generation complete. PDF and JSON reports have been saved."
        
        except Exception as e:
            nemesysLogger.error(f"❌ Error during report generation: {e}")
            return f"Error during report generation: {e}"

    def _split_log_into_chunks(self, log_file_path):
        """
        Splits the log file into smaller chunks to facilitate better processing with RAG.

        Args:
            log_file_path (str): The path to the system enumeration log file.

        Returns:
            list: A list of document chunks created from the log file content.
        """
        with open(log_file_path, 'r') as file:
            log_data = file.read()

        # Split the log into chunks for better processing
        chunk_size = 4500
        text_splitter = CharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=0)
        nemesysLogger.info(f"🔪 Splitting log into chunks of size {chunk_size}...")
        return text_splitter.create_documents([log_data])

    def _generate_pdf_report(self, analysis, file_path="nemesys_report.pdf"):
        """
        Generates a PDF report from the analysis results.

        Args:
            analysis (str): The security analysis generated by the model.
            file_path (str): The path to save the generated PDF report (default is "nemesys_report.pdf").
        """
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", style='B', size=16)
            pdf.cell(200, 10, txt="Nemesys Security Report", ln=True, align='C')
            pdf.ln(10)

            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=analysis.get("result", ""))
            pdf.ln(10)

            pdf.output(file_path)
            nemesysLogger.info(f"📄 PDF report generated: {file_path}")

        except Exception as e:
            nemesysLogger.error(f"❌ Failed to generate PDF report: {e}")

    def _generate_json_report(self, analysis, file_path="nemesys_report.json"):
        """
        Generates a JSON report from the analysis results.

        Args:
            analysis (str): The security analysis generated by the model.
            file_path (str): The path to save the generated JSON report (default is "nemesys_report.json").
        """
        try:
            with open(file_path, 'w') as json_file:
                json.dump({"analysis": analysis}, json_file, indent=4)
            nemesysLogger.info(f"💾 JSON report generated: {file_path}")
        except Exception as e:
            nemesysLogger.error(f"❌ Error generating JSON report: {e}")


    def _create_report_prompt(self):
        """
        Creates a detailed and structured prompt for generating the security report.

        Returns:
            str: The formatted prompt string for the model.
        """
        return (
            "You are an AI cybersecurity expert analyzing system enumeration data. Your task is to generate a comprehensive, "
            "detailed, and professional security report based on the provided log file. The report should include clear explanations, "
            "actionable insights, and specific examples when available. The report must cover the following sections:\n\n"

            "1. **Executive Summary**: \n"
            "Provide a brief summary of the overall findings, highlighting the most critical vulnerabilities and issues detected. "
            "Include a risk rating (e.g., Low, Medium, High) based on the severity of the identified threats. Mention the primary "
            "areas of concern and the potential impact on the system's security.\n\n"

            "2. **Introduction**: \n"
            "Introduce the analysis by outlining the type of system being reviewed (e.g., Linux server, Windows workstation), its purpose, "
            "and the context of the security evaluation. Explain why a thorough review of system logs, configurations, and active services "
            "is vital for maintaining security. Mention the data sources analyzed, such as system logs, configurations, and running services.\n\n"

            "3. **System Overview**: \n"
            "Summarize key information about the operating system (OS), kernel version, and system architecture. Identify any known or potential "
            "vulnerabilities related to these components. Explain how outdated versions or unsupported OS/kernel versions may increase security risks, "
            "and provide examples of common exploits that could be used against these vulnerabilities.\n\n"

            "4. **Identified Vulnerabilities and Risks**: \n"
            "List the detected vulnerabilities based on the enumeration data. This includes kernel vulnerabilities, misconfigured services, outdated packages, "
            "and weak system configurations. For each vulnerability, explain its severity, why it is considered risky, and how it could be exploited by an attacker. "
            "Provide specific examples or CVE references when applicable.\n\n"

            "5. **Insecure Configurations**: \n"
            "Highlight any configuration issues that could pose a security risk. This may include improper file permissions, exposed ports, vulnerable services, "
            "and other risky settings. For each issue, explain why it is problematic, how it can be detected, and the potential impact if left unaddressed.\n\n"

            "6. **Running Services Analysis**: \n"
            "Provide an analysis of the active services on the system. Identify any unnecessary or insecure services that should be disabled. "
            "Discuss why certain services might present a security concern, such as outdated software or services unnecessarily exposed to the internet. "
            "Recommend actions to secure or disable these services.\n\n"

            "7. **Network Security Assessment**: \n"
            "Analyze the network configurations, including open ports, firewall settings, and any detected network security flaws. Provide details about the services "
            "running on open ports and assess their potential vulnerabilities. Explain how attackers might exploit these open ports to gain unauthorized access.\n\n"

            "8. **Elevated Accounts and Potential Malware Detection**: \n"
            "Identify any elevated (privileged) user accounts, such as root or admin users, and discuss any risks associated with their usage. "
            "Check for any signs of malware or infections based on unusual processes or system behaviors. Provide details on how these elevated accounts "
            "or detected malware could compromise system security.\n\n"

            "9. **Security Recommendations**: \n"
            "Offer a set of clear, actionable recommendations to address the identified vulnerabilities and improve system security. Each recommendation should "
            "include specific steps, such as applying patches, configuring firewalls, securing user permissions, or disabling unnecessary services. "
            "Prioritize these actions based on the severity and potential impact of the issues.\n\n"

            "10. **Detected Anomalies**: \n"
            "Report any unexpected findings or anomalies in the system, such as unknown services, unusual log entries, or unexpected behaviors. "
            "Discuss the significance of these anomalies and whether they may indicate malicious activity or misconfigurations. Provide possible explanations "
            "and steps for further investigation.\n\n"

            "11. **Conclusion**: \n"
            "Summarize the overall security posture of the system, highlighting the main findings and areas for improvement. Emphasize the importance of "
            "addressing the critical issues identified in the report to enhance system security and reduce potential risks.\n\n"

            "The report should be structured, thorough, and use professional language. Ensure that the explanations are clear, detailed, and provide valuable insights "
            "to help system administrators understand the security issues and implement the recommended fixes effectively."
        )




       