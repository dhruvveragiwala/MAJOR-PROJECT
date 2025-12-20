import gradio as gr
import sys
import os

# Add the current directory to sys.path so local modules can be imported
sys.path.insert(0, os.path.dirname(__file__))

# Lazy import of `query_data` functions with safe fallbacks so the UI can start
# even if heavy ML libs (transformers / torch) are not installed.
try:
    from query_data import query_llm, query_rag
except Exception as e:
    # Fallback implementations. Try to call local tools from `primary_agent` if
    # available so the UI can perform pentest actions even when heavy ML libs
    # (transformers/torch) are missing. Otherwise fall back to a simple mock.
    try:
        import primary_agent
    except Exception:
        primary_agent = None

    def query_llm(query_text):
        # Very small mock LLM reply so basic tab works offline
        yield [{"content": f"(mock) LLM reply to: {query_text}"}]

    def query_rag(role, query_text):
        # Call the actual query_rag_agent from primary_agent to use the pentesting tools
        try:
            import primary_agent
            responses = primary_agent.query_rag_agent(query_text, [])
            for response in responses:
                yield [{"content": response['content']}]
        except Exception as e:
            yield [{"content": f"Error calling agent: {e}. Falling back to mock."}]
            yield [{"content": f"(mock) RAG reply for role={role}: {query_text}"}]

def create_chat_interface(fn, placeholder, title, description, examples=None):
    """
    Function to create a professional and clean chat interface.
    """
    def process_query(role, query_text, history=None):
        """
        Process the query, filter context by user role, and update chat history.
        """
        if history is None:
            history = []

        # Initialize the response string
        response_text = ""

        # Consume the generator function (query_rag)
        for step in fn(role, query_text):
            response_text += step[0]['content'] + "\n"

        # Append user query and assistant response to history
        history.append({'role': 'user', 'content': f"[{role}] {query_text}"})
        history.append({'role': 'assistant', 'content': response_text})

        return history, history  # Return updated history for Chatbot and State

    return gr.Interface(
        fn=process_query,
        inputs=[
            gr.Radio(choices=["External", "Internal"], label="Select User Role"),
            gr.Textbox(placeholder=placeholder, container=False, scale=7),
            gr.State()  # State to manage the chat history
        ],
        outputs=[
            gr.Chatbot(height=300),
            gr.State()  # Display and update chat history
        ],
        title=title,
        description=description,
    )

def create_chat_interfacee(fn, placeholder, title, description, examples=None):
    """
    Function to create a professional and clean chat interface without role selection.
    """
    def process_query(query_text, history=None):
        """
        Process the user query and update chat history.
        """
        if history is None:
            history = []

        # Call the LLM function and accumulate the response
        response = ""
        for step in fn(query_text):  # Consume the generator
            response = step[-1]['content']  # Get the latest assistant content

        # Update the history
        history.append({'role': 'user', 'content': query_text})
        history.append({'role': 'assistant', 'content': response})

        return history, history  # Return updated history for Chatbot and State

    return gr.Interface(
        fn=process_query,
        inputs=[
            gr.Textbox(placeholder=placeholder, container=False, scale=7),
            gr.State()  # State to manage the chat history
        ],
        outputs=[
            gr.Chatbot(height=300),
            gr.State()  # Display and update chat history
        ],
        title=title,
        description=description,
    )

# Define the interfaces
basic_interface = create_chat_interfacee(
    fn=query_llm,
    placeholder="Ask me any question.",
    title="SBI-CS-GPT 0.1 - Basic LLM",
    description="Engage with the basic LLM model for general queries.",
)

rag_interface = create_chat_interface(
    fn=query_rag,
    placeholder="Ask a question related to additional training data.",
    title="SBI-CS-GPT 0.1 - RAG",
    description="Interact with the LLM that incorporates retrieval-augmented generation (RAG).",
)

pentest_interface = create_chat_interface(
    fn=query_rag,
    placeholder="Enter a URL or command for pentesting (e.g., www.google.com).",
    title="Pentest Agent",
    description="Use cybersecurity tools for vulnerability scanning and analysis.",
)

# Combine all interfaces into a tabbed layout for easy navigation
demo = gr.TabbedInterface([basic_interface, rag_interface, pentest_interface], 
                          ["LLM BASIC", "LLM RAG", "PENTEST AGENT"])

# Launch the application
if __name__ == "__main__":
    # Pass runtime-only params to launch() in Gradio 6+
    demo.launch(share=False, theme="soft", server_port=8000, inbrowser=True)
