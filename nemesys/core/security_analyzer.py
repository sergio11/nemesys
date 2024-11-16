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
            pdf.multi_cell(0, 10, txt=analysis.get("results", ""))
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
        Creates the prompt for generating the security report.

        Returns:
            str: The formatted prompt string for the model.
        """
        return """
            You are an AI cybersecurity expert tasked with analyzing system enumeration data. Based on the provided log file, 
            generate a detailed and professional security report. The report should include the following sections with clear 
            explanations and actionable insights:

            1. **Introduction**: 
            Provide a brief introduction to the system analysis. Include details on the type of system being analyzed (e.g., 
            Linux, Windows), its purpose, and a high-level summary of the security analysis approach. Mention the importance 
            of reviewing system logs and configurations to ensure security.

            2. **System Overview**: 
            Summarize the operating system (OS), kernel version, and any known or potential vulnerabilities related to these 
            components. Explain how the version of the OS and kernel may impact security, such as known exploits or support issues.

            3. **Vulnerabilities and Risks**: 
            Identify any potential vulnerabilities based on the enumeration data. This includes kernel vulnerabilities, risks 
            associated with running services, installed packages, and other system configurations. Provide detailed explanations 
            of why these vulnerabilities are risky and how they can be exploited by an attacker.

            4. **Insecure Configurations**: 
            Point out any risky configurations, including improper permissions, vulnerable services, exposed ports, or 
            misconfigurations. For each issue, explain why it's insecure, how it can be identified, and the potential risks 
            associated with these configurations.

            5. **Running Services**: 
            Analyze the running services and their associated risks. Include any unnecessary or insecure services that should 
            be disabled. Describe why certain services may be a security concern (e.g., outdated services, unnecessary services 
            exposed to the internet).

            6. **Network Security**: 
            Comment on any exposed ports, network configurations, firewall settings, or network security flaws. Include details 
            about services running on open ports and their potential vulnerabilities. Provide an explanation of how attackers 
            may use these open ports to compromise the system.

            7. **Elevated Accounts and Malware**: 
            Identify any elevated user accounts (e.g., root/admin) and any signs of malware or infections. Provide details on 
            how these elevated accounts may be abused and the potential impact of malware on system security.

            8. **Security Recommendations**: 
            Provide actionable steps for mitigating risks, patching vulnerabilities, and improving system security. Each 
            recommendation should include practical steps, such as patching software, configuring firewalls, and securing user permissions.

            9. **Anomalies**: 
            Report any unexpected findings in the system, such as unusual log entries, unknown services, or anything that seems 
            out of the ordinary. Explain the significance of these anomalies and their potential to indicate malicious activity 
            or misconfigurations.

            Throughout the report, ensure to provide detailed explanations and actionable insights that would help system 
            administrators understand the security posture of the system and how to address any risks or vulnerabilities 
            identified. Ensure that the final report is structured, professional, and clearly explains each section in detail, 
            with a focus on improving system security.
        """



       