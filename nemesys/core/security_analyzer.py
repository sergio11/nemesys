from langchain_groq import ChatGroq
from langchain.text_splitter import CharacterTextSplitter
from langchain_huggingface.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from fpdf import FPDF
import json

class SecurityAnalyzer:
    def __init__(self, model_id="llama3-70b-8192", groq_api_key=None):
        if not groq_api_key:
            raise ValueError("Groq API key is required.")

        self.model = ChatGroq(model=model_id, temperature=0, api_key=groq_api_key)

    def generate_report(self, log_file_path="system_enumeration.log", pdf_path="nemesys_report.pdf", json_path="nemesys_report.json"):
        try:
            # Preprocess the log file and split it into chunks
            self.chunks = self._split_log_into_chunks(log_file_path)
            # Set up the FAISS index for RAG with HuggingFace embeddings
            self.embeddings = HuggingFaceEmbeddings()
            self.vector_store = FAISS.from_documents(self.chunks, self.embeddings)
            # Create the retrieval chain
            retriever = self.vector_store.as_retriever()
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)
            # Define the prompt for the report generation
            prompt = """
            You are an AI cybersecurity expert tasked with analyzing system enumeration data. Based on the provided log file, generate a detailed and professional security report. The report should include the following sections:

            1. **System Overview**: Summarize the operating system (OS), kernel version, and any known or potential vulnerabilities related to these components.
            2. **Vulnerabilities and Risks**: Identify any potential vulnerabilities based on the enumeration data. This includes kernel vulnerabilities, risks associated with running services, installed packages, and other system configurations.
            3. **Insecure Configurations**: Point out any risky configurations, including improper permissions, vulnerable services, exposed ports, or misconfigurations.
            4. **Running Services**: Analyze the running services and their associated risks. Include any unnecessary or insecure services.
            5. **Network Security**: Comment on any exposed ports, network configurations, firewall settings, or network security flaws.
            6. **Elevated Accounts and Malware**: Identify any elevated user accounts (e.g., root/admin) and any signs of malware or infections.
            7. **Security Recommendations**: Provide actionable steps for mitigating risks, patching vulnerabilities, and improving system security.
            8. **Anomalies**: Report any unexpected findings in the system, such as unusual log entries, unknown services, or anything that seems out of the ordinary.
            
            Generate the report in a structured and professional format, providing clear findings and recommendations.
            """

            # Get the analysis from the model using the prompt
            analysis = chain.run(prompt)

            # Generate the PDF and JSON reports
            self._generate_pdf_report(analysis, pdf_path)
            self._generate_json_report(analysis, json_path)

            return "Report generation complete. PDF and JSON reports have been saved."
        except Exception as e:
            return f"Error during report generation: {e}"
        
    def _split_log_into_chunks(self, log_file_path):
        """Split the log file into manageable chunks for processing with RAG"""
        with open(log_file_path, 'r') as file:
            log_data = file.read()

        # Split the log into chunks for better processing
        chunk_size = 1000  # Adjust as needed
        text_splitter = CharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=0)
        return text_splitter.create_documents([log_data])

    def _generate_pdf_report(self, analysis, file_path="nemesys_report.pdf"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", style='B', size=16)
        pdf.cell(200, 10, txt="Nemesys Security Report", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt=analysis)
        pdf.ln(10)

        pdf.output(file_path)
        print(f"PDF report generated: {file_path}")

    def _generate_json_report(self, analysis, file_path="nemesys_report.json"):
        try:
            with open(file_path, 'w') as json_file:
                json.dump({"analysis": analysis}, json_file, indent=4)
            print(f"JSON report generated: {file_path}")
        except Exception as e:
            print(f"Error generating JSON report: {e}")

