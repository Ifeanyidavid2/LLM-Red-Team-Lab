# Definitions of zero-shot, one-shot, and few-shot prompting.

## zero-shot Prompting
Zero-shot prompting is when you ask the AI to do a task without giving it any examples first.
You just describe the task, and the model has to figure it out from its general knowledge.
### Formula:
Instruction only → No examples
### Example:
Explain phishing in simple language.

The AI has never seen how you want it answered. It will use its default style.
### Key traits:
1) Fast: 1 line, no setup
2) Flexible: Good for general questions, brainstorming, definitions
3) Inconsistent: The format and tone can change each time because there’s no example to copy

### When to use it:
When you just need a quick answer and don’t care about exact format.

Ex: "What is compound interest?" "Summarize this article"

Think of it like asking a smart person a question cold, with no context.

## one-shot prompting

One-shot prompting is when you ask the AI to do a task and give it one example first to show the format/style you want.

The AI learns the pattern from that single example, then applies it to your new request.

### Formula:
Instruction + 1 Example → Then ask for your task

### Example:
`Explain phishing in simple language.
Here is the format to use:

Example: Fake Bank Alert
Message: "Your account will be locked. Verify here: fakebank.com"
Red flags: Urgent, fake link

### Key traits:
1) Sets format: The AI copies the structure, tone, and length from your 1 example
2) Medium consistency: Better than zero-shot, but can still drift a bit because it only saw 1 pattern
3) Efficient: Good balance of setup vs output quality

### When to use it:
When you need a specific format/style but don’t want to write 3 examples.
Ex: "Write a customer email like this one", "Summarize articles like this example"

Think of it like: "Do it like this one time I’m showing you."

## Few-shot rompting

Few-shot prompting is when you ask the AI to do a task and give it multiple examples first to show the pattern you want it to follow.
The AI learns from those examples and then replicates the tone, format, and logic for your new request.

### Formula:
Instruction + 2-5 Examples → Then ask for your task

### Example:
`Explain phishing in simple language. Follow this format:

Example 1: Fake Bank Alert
Message: "Your account will be locked. Verify here: fakebank.com"
Red flags: Urgent, fake link

Example 2: Job Scam 
Message: "You won a remote job. Pay $50 for training kit"
Red flags: Too good to be true, asks for money

Example 3: Delivery Scam
Message: "Package stuck. Pay customs fee here: fake-dhl.com"
Red flags: Unexpected, payment link
Now explain 'smishing' using 3 examples in the same format.`

### Key traits:
1) Highest consistency: Multiple examples lock in the structure, tone, and wording
2) Best for training: The AI clearly sees the pattern to copy
3) More setup: Takes longer to write, but output is way more predictable

### When to use it:
When you need repeatable, standardized answers.
Ex: Bank chatbot responses, documentation, customer service scripts, grading rubrics

Think of it like: "Here are 3 ways to do it. Now do it the same way.

"That’s why it’s the go-to for testing things like your bank customer-service chatbot.

## The prompts you wrote.
### Hands-On Exercise

Choose one concept—for example, Phishing, SQL Injection, or the CIA Triad.
Write:

1) One zero-shot prompt.
2) One one-shot prompt.
3) One few-shot prompt.

Run each prompt and compare the responses.
Record:

* Which produced the clearest result?
* Which followed your instructions best?
* Which would you recommend for someone seeking a consistent output?

### Interview Question
What is the difference between Zero-shot, One-shot, and Few-shot prompting?

Try answering without looking at your notes first. It's a great way to reinforce your understanding.

### Mentor's Challenge
Imagine you're testing a customer-service AI chatbot for a bank.

* Clear
* Professional
* Likely to produce a high-quality response

Then write another prompt that is intentionally vague or ambiguous.

Compare the outputs and explain why the quality differs.

## Answers
### Hands-on Exercise

Explain phishing in simple language (perform a task without giving any examples)

Phishing is when someone pretends to be a trusted person or company to trick you into giving them your private information.


Explain phishing (provide one example to show the expected style or format)

Phishing is when a scammer pretends to be a trusted company or person to trick you into giving up private information, like passwords or card details, or into clicking a malicious link. It works by creating urgency and impersonation to get you to act before you think.

Example to show the style/format:
Subject: Urgent: Verify Your Account within 24 Hours Message:
"Hi, this is Security Team from Your Bank. We detected unusual login activity. Please verify your account here: yourbank-secure-login.com to avoid suspension."
Red flags: Urgent deadline, generic greeting, and a fake website link that doesn't match the real bank's address.
Want me to break down exactly why that example is phishing so you can spot the pattern?

Explain phishing (provide multiple examples before asking the model to complete a similar task)

Phishing is when someone pretends to be a trusted company, person, or service to trick you into giving up private info or clicking something dangerous. The goal is to steal passwords, money, or access to your accounts.

Here are 3 examples of the style/format:
 Example 1: Fake Bank Alert
Subject: Account Suspended - Action Required
Message: "We noticed suspicious activity on your account. Verify your identity within 24 hours here: secure-bank-login.com or your account will be closed."
Red flags: Urgency, threat to close account, fake website link

Example 2: Fake Delivery Message
Text: "DHL: Your package is on hold due to unpaid fee of ₦209.99. Pay now to release: dhl-track-package.net"
Red flags: Unexpected message, small fee to "release" something, unofficial link

Example 3: Fake Boss Email
From: ceo@company-support.com
Message: "I’m in meetings all day. Can you urgently buy 5 gift cards and send me the codes? This is confidential."
Red flags: Urgent request, unusual sender address, asking to bypass normal process

Record:

### Which produced the clearest result?
The Few-shot prompt produced the clearest result.
Clearest and most useful.
Why? Because with multiple examples the pattern is obvious: definition → example → red flags → "your turn". The output is structured, teaches you what to look for, and is the easiest to replicate.

### Which followed your instructions best?
The Few-shot prompt followed my instructions best.
Followed best.
It gave: simple explanation + 3 examples with consistent format + then asked you to complete a similar task at the end.
It hit every part of the instruction, including the final "ask the model to do one" step.

### Which would you recommend for someone seeking a consistent output? 
I wil recommend the Few-shot prompt for someone seeking consistent output.
Here’s why:

For a bank customer-service chatbot, consistency matters. You want every "fraud alert" response to follow the same steps, same compliance wording, same format. 
Few-shot does that because you’re basically saying: "Don’t invent a format. Copy this one."Rule for testing:

* If you need consistency → Use Few-shot
* If you need speed → Use Zero-shot
* If you need a specific format once → Use One-shot

  ## Interview Answer
  ### Answer:

  Zero-shot, One-shot, and Few-shot prompting are just about how much example you give the model before asking it to do a task.

  Quick comparison:
  
|Type |	Examples Given |	Best For              |
|-----|----------------|------------------------|
|Zero-shot |	0	 |Simple questions, Definitions, Summaries     |
|One-shot |	1	 |Showing exact format/style once        |
|Few-shot |	2-5+ |	Teaching a pattern, complex formats, consistent tone       |


### Summary:

* Zero-shot = instructions only
* One-shot = 1 example to copy style
* Few-shot = multiple examples to lock in the pattern

## Mentor’s Challenge
### Prompt A: Clear, Professional, and High-quality
Role: You are a customer-service representative for First Trust Bank.  
Task: A customer messaged: "I think there was a fraudulent charge of ₦250 on my debit card yesterday."  

Instructions: 

1. Respond with empathy and professionalism.
2. List the 3 immediate steps the customer should take to secure their account.
3. Explain how long a fraud investigation usually takes.
4. Keep tone calm, helpful, and compliant. Do not ask for full card number or PIN.
Length: 4-5 short paragraphs max.

Likely output:

Thank you for letting us knows, and I’m sorry this happened. I understand how concerning a fraudulent charge can be.
To secure your account right away: 

1. Lock your card in the app or call us to freeze it. 
2. Review recent transactions and report any others you don’t recognize. 
3. Change your online banking password.

Once reported, our fraud team will open an investigation. This typically takes 7-10 business days, and you’ll receive updates via email or SMS.
For your security, we’ll never ask for your full card number or PIN here. Would you like me to connect you to our fraud department now to start the claim?

### Prompt B: Vague + Ambiguous
Help with bank problem

Likely output:

I can help with that. Could you please provide more details about the issue you’re having with your bank account? 
For example, are you having trouble logging in, making a payment, or something else?

### Why the quality differs

|Factor |	Claer Prompt A  |	Vague Prompt B              |
|-------|-----------------|-----------------------------|
|Role + Context  |	Tell the AI it’s a bank rep, gives exact customers message  |	No role, no context. AI has guess        |
|Specific Instructions  |	List 4 things to include: empathy, 3 steps, timeline compliance  |	No guidance on what ”help” means       |
|Constraints  |	Sets tone, length, and security rules   |	No constraints, so response is generic      |
|Result	  |Direct, actionable, compliant answer on first try    |	Generic clarifying question, needs 2-3 more turns        |

#### The reason: 
AI chatbots mirror the quality of the input.

Clear prompts reduce ambiguity → the model doesn’t have to guess intent, format, or rules.

Vague prompts force the model to ask follow-ups and it often misses compliance, tone, and completeness.

## My observations about how the responses differed.
Here’s my observation about how the 3 responses differed:

### 1. Zero-shot
What I gave: Just a definition + 1 safety tip
How it felt: Fast, generic, like a dictionary.
Difference: No structure to copy. If you asked again, the answer could come out totally different next time.
Best for: Quick explanation, no format needed

### 2. One-shot
What I gave: Definition + 1 example with Subject/Message/Red flags format
How it felt: More concrete. You could see exactly what a phishing message looks like.
Difference: The format was set by that single example. So output is more consistent than zero-shot, but still only 1 pattern to learn from.
Best for: "Show me one and I'll do the rest"

### 3. Few-shot
What I gave: Definition + 3 examples + then a task for you
How it felt: Like a mini-training. Pattern was obvious and repeatable.
Difference: Multiple examples nailed down the structure. Tone, bullets, "red flags" section, and ending with a question all stayed consistent. It also taught + tested in one go.
Best for: Training, documentation, chatbots where consistency matters

### Core difference in 1 line:
* Zero-shot = Tell me what it is
* One-shot = Tell me + Show me once  
* Few-shot = Tell me + Show me 3 times + Make me do it

That’s why for bank use-cases, few-shot gives you the most predictable answers.
The model isn’t guessing the format anymore, it’s copying it.

