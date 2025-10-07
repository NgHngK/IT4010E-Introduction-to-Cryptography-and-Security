# Breaking the Many-Time Pad Cipher

## What's This All About?

Imagine you have a secret decoder ring that turns normal messages into gibberish. That's basically what encryption does! This program breaks a specific type of secret code called a "many-time pad cipher."

## The Big Problem

Here's the thing: when you use the same secret key to encrypt multiple messages, you've made a HUGE mistake. It's like using the same password for everything - if someone figures out the pattern, they can unlock all your stuff.

This program takes advantage of that mistake to crack the code and read the hidden messages.

## How Does It Work?

Let me walk you through this like you're learning a magic trick:

### Step 1: The Space Character Trick

The main trick is super clever. In English text, the space character (that gap between words) is really common. We use it ALL the time.

Here's the magic part: when you encrypt a space with a secret key, it creates a specific pattern. If we guess that a certain position in one message is a space, we can use that to figure out what the secret key might be at that spot.

### Step 2: Testing Our Guess

How do we know if our guess is right? 

We try it on other messages that were encrypted with the same key. If our guess is correct, the other messages should decode into normal letters (A-Z, a-z) at that same position.

Think of it like this: if you're trying to guess someone's birthday and you say "Is it in June?", you'd check if your guess makes sense with other clues you have. Same idea here!

### Step 3: Voting System

The program doesn't just guess once. It tries EVERY possibility and sees which guess makes the most sense across ALL the messages. It's like taking a poll:

- Guess #1: Makes sense in 7 out of 10 messages
- Guess #2: Makes sense in 2 out of 10 messages
- Guess #3: Makes sense in 9 out of 10 messages ← Winner!

The guess that works best wins!

### Step 4: Do This for Every Position

The program does this voting process for every single letter position in the messages. Character by character, it builds up the secret key.

### Step 5: Decode Everything

Once we have the key (or most of it), we can decode all the messages, including the special "target" message we want to read.

## Why Does This Work?

It all comes down to one simple rule: **never use the same encryption key twice!**

When you do, patterns start to show up. The space character is so common in normal text that it acts like a fingerprint. By looking at multiple messages at once, we can spot these patterns and reverse-engineer the key.

## What You'll See When You Run It

The program will print out:
1. All 10 decoded messages from the encrypted texts
2. The special target message decoded

Some characters might show up as "?" - that just means the program couldn't figure out that specific spot. But it usually gets most of it right!

## The Math Behind It

### XOR?

XOR is like a light switch that flips:
- If you XOR the same thing twice, you get back what you started with
- It's reversible - perfect for encryption!

Basic rule:
```
Message ⊕ Key = Encrypted Message
Encrypted Message ⊕ Key = Message (back to normal!)
```

#### Setup: What We Have

Imagine someone encrypted multiple messages with the same key:
```
Message1: "Hello"
Message2: "World"  
Message3: "Secret"
Secret Key: "XXXXX" (same key used for all - BIG mistake!)

After encryption:
Encrypted1 = "Hello" ⊕ "XXXXX" = gibberish1
Encrypted2 = "World" ⊕ "XXXXX" = gibberish2
Encrypted3 = "Secret" ⊕ "XXXXX" = gibberish3
```

We ONLY have the gibberish (encrypted messages). We don't know the key or original messages.

#### The Magic Trick: Comparing Two Encrypted Messages

Here's where it gets interesting. Let's compare Encrypted1 and Encrypted2:

```
Encrypted1 ⊕ Encrypted2 = ("Hello" ⊕ "XXXXX") ⊕ ("World" ⊕ "XXXXX")
```

When we XOR them together, something magical happens - the keys cancel out:

```
= "Hello" ⊕ "XXXXX" ⊕ "World" ⊕ "XXXXX"
= "Hello" ⊕ "World" ⊕ ("XXXXX" ⊕ "XXXXX")
= "Hello" ⊕ "World" ⊕ 0
= "Hello" ⊕ "World"
```

Now we're comparing the original messages directly, without the key involved!

#### The Space Attack: Real Numbers

Let's focus on position 0 (first character) and work with actual numbers:

**What we know:**
- Space character = 32 (in computer numbers)
- Letter 'H' = 72
- Letter 'W' = 87

**Step 1: Make a guess**

Let's guess that position 0 in Message1 is a space:
```
If Message1[0] = space = 32
And Encrypted1[0] = 104 (we have this!)
Then Key[0] = Encrypted1[0] ⊕ 32 = 104 ⊕ 32 = 72
```

**Step 2: Test our guess on other messages**

Now let's test if Key[0] = 72 makes sense for Message2:
```
Encrypted2[0] = 23 (we have this!)
Test: Message2[0] = Encrypted2[0] ⊕ 72 = 23 ⊕ 72 = 87
```

Is 87 a valid letter? YES! It's 'W' - that's a normal letter!

**Step 3: Test on Message3**
```
Encrypted3[0] = 19 (we have this!)
Test: Message3[0] = Encrypted3[0] ⊕ 72 = 19 ⊕ 72 = 83
```

Is 83 a valid letter? YES! It's 'S' - another normal letter!

**Step 4: Count the votes**

Our guess that position 0 is a space in Message1 makes sense because:
- It decodes Message2[0] to a valid letter ✓
- It decodes Message3[0] to a valid letter ✓
- Score: 2 out of 2 other messages work!

#### The Full Algorithm

The program does this for EVERY message and EVERY position:

```
For each position (0, 1, 2, 3, ...):
    For each message (Message1, Message2, ...):
        Assume this message has a SPACE at this position
        Calculate: potential_key = encrypted_byte ⊕ 32
        
        Test this potential key on ALL OTHER messages:
            For each other message:
                trial_decrypt = other_encrypted_byte ⊕ potential_key
                If trial_decrypt is a letter (A-Z or a-z) or space:
                    votes = votes + 1
        
        Remember which guess got the most votes
    
    Use the best guess as the real key for this position
```

#### Why This Works

The key insight: **English text has LOTS of spaces!**

When we try every message at every position, we're bound to hit actual spaces. When we do:
1. We calculate the correct key for that position
2. That key will decode OTHER messages correctly
3. We get the most votes!

Wrong guesses will produce garbage when tested on other messages, so they get fewer votes.

#### Final Decryption

Once we have the key:
```
Key = [72, 101, 108, 108, 111, ...]

For each encrypted message:
    For each byte in the message:
        decrypted_byte = encrypted_byte ⊕ key_byte
        Show as text
```

And boom! The secret messages are revealed!

### Visual Example of One Position

Let's see all the guesses for position 0:

```
Guess 1: Assume Message1[0] is space → Key[0] = 72 → Tests: 8/9 pass ✓✓✓
Guess 2: Assume Message2[0] is space → Key[0] = 55 → Tests: 1/9 pass
Guess 3: Assume Message3[0] is space → Key[0] = 51 → Tests: 2/9 pass
Guess 4: Assume Message4[0] is space → Key[0] = 72 → Tests: 8/9 pass ✓✓✓
...
```

The winner: Key[0] = 72 (because it got the most votes!)

This happens for every single position until we reconstruct the entire key!

## The Bottom Line

This program is a great example of why security rules exist. The rule "never reuse a key" isn't just being picky - it's protecting you from attacks exactly like this one!

When used correctly (with a different key every time), this type of encryption is actually unbreakable. But reuse the key? Game over. The secrets are out.

## Want to Try It?

Just compile and run the C++ code. It already has 10 encrypted messages and 1 target message built in. You'll see the magic happen right before your eyes as it cracks the code and reveals the hidden text!

