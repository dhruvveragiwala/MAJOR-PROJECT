import gradio as gr
import sys
import os

# Add the current directory to sys.path so local modules can be imported
sys.path.insert(0, os.path.dirname(__file__))

# Lazy import of `query_data` functions with safe fallbacks so the UI can start
# even if heavy ML libs (transformers / torch) are not installed.
try:
    from query_data import query_rag
except Exception as e:
    # Fallback implementations. Try to call local tools from `primary_agent` if
    # available so the UI can perform pentest actions even when heavy ML libs
    # (transformers/torch) are missing. Otherwise fall back to a simple mock.
    try:
        import primary_agent
    except Exception:
        primary_agent = None

    def query_rag(query_text):
        # Call the actual query_rag_agent from primary_agent to use the pentesting tools
        try:
            import primary_agent
            responses = primary_agent.query_rag_agent(query_text, [])
            for response in responses:
                yield [{"content": response['content']}]
        except Exception as e:
            yield [{"content": f"Error calling agent: {e}. Falling back to mock."}]
            yield [{"content": f"(mock) RAG reply for: {query_text}"}]


def create_pentest_interface(fn, placeholder, title, description, examples=None):
    """
    Pentest interface with only one input box (URL/command) and chat history.
    """
    def process_query(query_text, history=None):
        """
        Process the query and update chat history.
        """
        if history is None:
            history = []

        response_text = ""

        # fn is a generator (query_rag)
        for step in fn(query_text):
            response_text += step[0]['content'] + "\n"

        history.append({'role': 'user', 'content': query_text})
        history.append({'role': 'assistant', 'content': response_text})

        return history, history

    return gr.Interface(
        fn=process_query,
        inputs=[
            gr.Textbox(
                placeholder=placeholder,
                container=False,
                scale=7,
                label="Target URL or command",
            ),
            gr.State()
        ],
        outputs=[
            gr.Chatbot(height=300),
            gr.State()
        ],
        title=title,
        description=description,
    )


# Only the Pentest Agent interface
pentest_interface = create_pentest_interface(
    fn=query_rag,
    placeholder="Enter a URL or command for pentesting (e.g., https://example.com).",
    title="Pentest Agent",
    description="Use cybersecurity tools for vulnerability scanning and analysis.",
)

demo = pentest_interface

if __name__ == "__main__":
    demo.launch(share=False, theme="soft", server_port=8001, inbrowser=True)
