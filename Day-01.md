# Questions
## Hands-On Exercise

Choose one publicly available chatbot (for example, ChatGPT, Gemini, or another assistant you have access to).

Try these prompts:

1. Explain the CIA Triad in simple terms.
2. Explain it again for a 10-year-old.
3. Explain it as if speaking to a CEO.
4. Summarize it in one sentence.

Observe how the responses change depending on the audience and instructions.

Write down:

What changed?
What stayed consistent?
Did the model follow your instructions?

## Mini Assignment

Write a one-page document titled:

"What I Learned About Large Language Models"

Include:

1. What an LLM is.
2. What a token is.
3. What a context window is.
4. The difference between training and inference.
5. Why LLM security matters.
6. One question you'd like to explore further.

Portfolio Task

Create a GitHub repository named:

LLM-Red-Team-Lab

Then add:

* A README.md
* A brief description of your goal
* A folder named Day-01

Even if the repository starts small, documenting your progress from the beginning shows consistency and growth.

## Mentor's Challenge

Think like a security professional:

If an LLM predicts text rather than "knowing" facts, how could that contribute to security risks?

Write your thoughts in 3–5 sentences. There isn't just one correct answer—the goal is to reason about how prediction-based systems might produce unreliable or unsafe outputs.

## Interview Question of the Day

What is the difference between training and inference in a Large Language Model?

# Answers
## Hands-On Exercise

What changed? 
* The model behaviour changed on the audience.

What stayed consistent?

* The topic (CIA Triad) remained consistent.
  
Did the model follow your instruction?

* Yes, the model followed my instruction.

## What I Learned About Large Language Models
1. I learned that Large Language Models (LLMs) is an AI model trained on a very large collection of text. It also learned statistical patterns in language, so it can predict the next token in a sequence.
Instead of storing the exact answers, an LLM estimates what token is most likely to come next based on the prompt and the patterns it learned during training.
‘’Large’’ refers to the scale of the model and the data used to train it.
This may include:
*	Billions of parameters
*	Massive datasets
*	Significant computing resources during training
   
More parameters do not automatically guarantee better performance, but they generally allow a model to represent more complex patterns.

2. I learned that LLMs do not read text word by word rather they process tokens, which are pieces of text. The exact tokenization depends on the model.

3. A context window is the amount of information the model can consider while generating a response. A longer context window lets a model work longer conversation or documents.

4. The difference between training and inference is that training is the process of learning from large datasets, while inference is the process of generating response after the model has been trained.

5. LLM security matters because unlike the traditional software, LLMs may:
-	Follow malicious or misleading instructions if they are not protected by appropriate safeguards, making prompt injection and jailbreak testing important.
-	Produce inaccurate information(hallucination)
-	Reveal sensitive information if poorly designed
-	Be influenced by prompt injection
-	Generate harmful or misleading content

6. I will like to explore further on why the LLM security matters.

Interview Question of the Day

## Interview Answer of the Day
* The difference between training and inference is that training is the process of learning from large datasets, while inference is the process of generating response after the model has been trained.


