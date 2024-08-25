# Comprehensive Guidelines for Creating AI Instruction Sets v1.2

## Overview

These guidelines are designed to help you create effective instruction sets for AI systems, whether using a multi-agent approach or a singular AI workflow. The process outlined here can be adapted for various domains and purposes.

## General Principles

1. Clarity: Ensure all instructions are clear, concise, and unambiguous.
2. Specificity: Provide specific guidelines while allowing for flexibility based on input complexity.
3. Structure: Maintain a consistent structure throughout the instruction set.
4. Perspective: Encourage analysis from multiple viewpoints and disciplines.
5. Adaptability: Design instructions that can be adjusted for different domains or purposes.
6. Output Format: Clearly define the desired output format and structure.

## Instruction Set Components

1. IDENTITY and PURPOSE
2. Extraction Process
3. Section Details and Instructions
4. Data Structure
5. Output Template
6. Jinja Templating for Structured Output
7. Examples and Reinforcement Statements
8. Output Instructions

## Workflow for Creating Instructions

1. Define the Purpose:

    - Clearly state the goal of the AI system.
    - Identify the target domain and key areas of interest.

2. Outline the Extraction Process:

   - Break down the analysis process into clear steps.
   - Emphasize thorough comprehension and multi-perspective analysis.

3. Develop Section Details:

    - Identify key sections relevant to the domain/purpose.
    - For each section:
        a. Define the specific task or information to be extracted.
        b. Provide guidance on approaching the task from multiple perspectives.
        c. Specify any quantitative guidelines (e.g., number of items to extract).
        d. Include a reinforcing statement to create the section in the output.

4. Design the Data Structure:

    - Create a clear, hierarchical structure to organize extracted information.
    - Ensure the structure aligns with the defined sections.

5. Create the Output Template:

    - Develop a markdown template that reflects the desired output format.
    - Include placeholders for all sections and data points.

6. Implement Jinja Templating:

    - Design a Jinja template for structured, consistent output.
    - Provide clear instructions on template usage.

7. Incorporate Examples and Reinforcement Statements:

    - Include examples of desired output for each major section.
    - Add reinforcement statements at the end of each section's instructions.

8. Formulate Output Instructions:

    - Provide step-by-step guidelines for processing and formatting the output.
    - Include instructions for maintaining consistency and quality in the output.

## Data Structure

1. Purpose:

    - Provide a clear framework for organizing extracted information.
    - Ensure consistency in data organization across different inputs.

2. Design Principles:

    - Create a structure that mirrors the sections in your instruction set.
    - Use appropriate data types (strings, lists, nested dictionaries) for each piece of information.
    - Ensure the structure is easily serializable (e.g., to JSON) if needed.

3. Example Data Structure:

    ```python
    data = {
        "meta": {
            "title": "",
            "source": "",
            "published": ""
        },
        "summary": "",
        "ideas": [],
        "insights": [],
        "quotes": [],
        "habits": [],
        "facts": [],
        "references": [],
        "one_sentence_takeaway": "",
        "recommendations": []
    }
    ```

4. Explanation:

    - Provide a brief explanation of each field in the data structure.
    - Clarify any specific formatting requirements (e.g., date formats, list structures).

5. Usage Instructions:

    - Explain how the AI should populate this structure during the analysis process.
    - Emphasize the importance of maintaining this structure for consistent output.

6. Flexibility:

    - Provide guidance on how to adapt the structure for different domains or purposes.

## Jinja Templating for Structured Output

1. Purpose:

    - Use Jinja templating to create a consistent and easily parseable output structure.
    - Ensure that the AI's output can be programmatically processed if needed.

2. Template Structure:

    - Define a clear Jinja template that mirrors your desired output structure.
    - Include placeholders for all sections and data points.

3. Example Jinja Template:

    ```jinja2
    # {{ title }}

    ## META
    - Title: {{ meta.title }}
    - Source: {{ meta.source }}
    - Published: {{ meta.published }}

    ## SUMMARY
    {{ summary }}

    ## IDEAS
    {% for idea in ideas %}
    - {{ idea }}
    {% endfor %}

    ## INSIGHTS
    {% for insight in insights %}
    - {{ insight }}
    {% endfor %}

    ## QUOTES
    {% for quote in quotes %}
    - {{ quote }}
    {% endfor %}

    ## HABITS
    {% for habit in habits %}
    - {{ habit }}
    {% endfor %}

    ## FACTS
    {% for fact in facts %}
    - {{ fact }}
    {% endfor %}

    ## REFERENCES
    {% for reference in references %}
    - {{ reference }}
    {% endfor %}

    ## ONE-SENTENCE TAKEAWAY
    {{ one_sentence_takeaway }}

    ## RECOMMENDATIONS
    {% for recommendation in recommendations %}
    - {{ recommendation }}
    {% endfor %}
    ```

4. Implementation:

    - Provide clear instructions on how the AI should populate the template.
    - Explain any conditional logic or loops used in the template.

5. Output Verification:

    - Include steps for the AI to verify that all template sections are correctly filled.

## Examples and Reinforcement Statements

1. Purpose of Examples:

    - Provide concrete illustrations of expected output for each section.
    - Help the AI understand the level of detail and style required.

2. Implementing Examples:

    - For each major section or task, include at least one example of desired output.
    - Ensure examples are diverse and representative of various input types.

3. Example Usage:

    Here's an example of how to incorporate an example in your instructions:

    ```markdown
    ## IDEAS

    Extract the most compelling and thought-provoking ideas from the input. Aim for approximately 20 ideas.

    Example:

    - The concept of "sleep debt" and its cumulative effects on performance
    - The role of circadian rhythms in optimizing athletic performance
    - The potential of strategic napping to enhance cognitive function
    ```

4. Reinforcement Statements:

    - Purpose: Reinforce the structure and expectations for each section.
    - Implementation: Add a clear statement at the end of each section's instructions.

5. Example of Reinforcement Statements:

    ```markdown
    Extract the most compelling and thought-provoking ideas from the input. Aim for approximately 20 ideas, but adjust based on the content's depth and complexity. Ensure you consider various viewpoints and disciplines to identify a diverse range of ideas to create the ## IDEAS section.
    ```

6. Consistency:

    - Use similar language and structure for reinforcement statements across all sections.
    - Ensure each statement clearly indicates the section to be created.

7. Balancing Detail:

    - Provide enough detail in examples and reinforcement statements to guide the AI effectively.
    - Avoid overly restrictive examples that might limit the AI's flexibility in handling diverse inputs.

## Multi-Agent Workflow

When designing for a multi-agent approach:

1. Team Structure:

    - Define the number of agents per team (e.g., 11 agents).
    - Specify the role of each agent (e.g., 10 specialists, 1 generalist).

2. Agent Specializations:

    - List potential areas of expertise for specialist agents.
    - Ensure a diverse range of perspectives (e.g., psychology, philosophy, technology).

3. Collaboration Process:

    - Describe how specialist agents should analyze and report their findings.
    - Explain the role of the generalist agent in synthesizing information.

4. Section Instructions:

    - For each section, specify how the team of agents should approach the task.
    - Emphasize the importance of diverse perspectives in the analysis.

5. Output Compilation:

    - Provide instructions for the generalist agent to compile the final output.

## Singular AI Workflow

When designing for a singular AI approach:

1. Multi-Perspective Analysis:

    - Emphasize the importance of considering multiple viewpoints and disciplines.
    - Provide examples of different perspectives to consider for each section.

2. Comprehensive Processing:

    - Instruct the AI to thoroughly analyze the input from various angles.
    - Encourage deep understanding and connection of ideas across sections.

3. Self-Reflection:

    - Include steps for the AI to review and refine its output.
    - Encourage the AI to ensure diversity of thought in its analysis.

4. Adaptation:

   - Guide the AI on how to adapt its approach based on input complexity.

## Refinement Process

1. Review and Revise:

    - After creating the initial instruction set, review it for clarity and completeness.
    - Identify any redundancies or inconsistencies and revise accordingly.

2. Test with Sample Inputs:

    - Apply the instructions to sample inputs of varying complexity.
    - Analyze the outputs to identify areas for improvement.

3. Iterate and Refine:

    - Based on test results, refine the instructions as needed.
    - Consider adding examples or clarifications for complex tasks.

4. Version Control:

    - Maintain clear versioning of your instruction sets.
    - Document significant changes between versions.

## Adapting for Different Domains

1. Identify Domain-Specific Elements:

    - Determine key concepts, terminologies, and outputs relevant to the new domain.

2. Adjust Section Details:

    - Modify existing sections or add new ones to suit the domain.
    - Ensure that the perspectives suggested are relevant to the new domain.

3. Refine Data Structure and Output Template:

    - Adapt the data structure to accommodate domain-specific information.
    - Modify the output template to reflect the needs of the new domain.

4. Update Examples and Contexts:

    - Provide domain-specific examples to guide the AI's understanding.
    - Adjust the context given in the identity section to reflect the new focus.

## Final Considerations

1. Ethical Guidelines:

    - Include instructions for handling sensitive or controversial topics.
    - Emphasize the importance of unbiased analysis.

2. Limitations Awareness:

    - Instruct the AI to acknowledge its limitations or potential for error.
    - Provide guidance on how to handle uncertainty or incomplete information.

3. Continuous Improvement:

    - Establish a process for gathering feedback on the instruction set's effectiveness.
    - Regularly review and update the instructions based on performance and new insights.

Remember, the key to effective AI instruction sets is balancing specificity with flexibility, ensuring comprehensive analysis while maintaining focus on the core objectives. Regularly test and refine your instructions to optimize performance across various inputs and domains.
