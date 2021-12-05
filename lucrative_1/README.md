# Lucrative Infiltration 1 @ ph0wn 2021

Lucrative Infiltration 1 is a challenge tagged "crypto".
Points: 350 points
Author: $in

## The challenge {#challenge-id}
You've been part of a shady hackerTs organization for a while now, and your team is preparing a big shot.

A new cryptocurrency, ph0wncoin is flooding the market and claiming to be THE nextgen currency. You know for a fact that this is not even close to be true, and that this is just a cover for a new centralized currency.

However, your team has been passively trying to find vulnerabilities to infiltrate the central server, located at challenges.ph0wn.org:12346, without success... The authentication mechanism seems strong enough and resisted all kind of enumerations and exploits, but today one of your pentester teammates managed to find an entrypoint to eavesdrop on what appears to be the authentication logs sent to an ELK instance : challenges.ph0wn.org:12345. A reverser from your team managed to build the source code generating these logs from the public client binary. It's now your job as a cryptanalyst to find a way to get into this server (a flag will be waiting for you there).

## Write-up

Credits to **AnomalRoil** on this one!!!

In addition to the [challenge's description](#challenge-id " "), we were given a [client python script](https://github.com/0xbaaf/ph0wn-2021/blob/main/lucrative_1/challenge/client.py "client.py").

### Client script analysises
The script encrypts a password under a key derived from the timestamp and two 32 bits unknown values (A and B).

For each block of plaintext (block size is 4 bytes), a key is drawn from a pseudo random generator. This pseudo random number generator (PRNG) is called [Linear Congruential Generator](https://en.wikipedia.org/wiki/Linear_congruential_generator "LCG") even if it is affine ... 

The PRNG is seeded with a timestamp and its coefficients are a 32-bits pair ($A$,$B$).

The knowledge of the timestamp, $A$ and $B$ allows to compute the keystream and thus decrypt the encrypted password.

The encryption function is used to encrypt a password read from the standard input.
The password is prepended by "ph0wn:" before it gets encrypted.
The encryption routine returns the encrypted password and the seed used (timestamps).

### Logs

Following [challenge's description](#challenge-id " "), there is an ELK instance where we can get authentication logs.

``` $ nc challenges.ph0wn.org 12345```

This provides logs that you can consult [here](https://github.com/0xbaaf/ph0wn-2021/blob/main/lucrative_1/solution/logs.txt "logs"). Here two log entries:

```
{'username': 'Wendel', 'timestamp': 1638553108, 'token': '11c26663ebab3e896e68df6dc949043a1c4345843b76d4c6ee20ba08', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'}

{'username': 'Wendel', 'timestamp': 1638553113, 'token': '11c2666e629f58d35d6133d96b704002b3e88854cf5fb66628afc748', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'}
```

At this stage I was not aware of this but these two logs (which where the first logs I've obtained) are sufficient to solve the challenge.

### Solution

The purpose of this challenge is to compute the key and decrypt _token_ (encrypted password) of an user.
The main issue to overcome is to retrieve _A_ and _B_ which are both 32 bits long. Brute forcing 64 bits is not an option so we need to figure out another way.


The first plaintext block $p_0$ is xored with the timestamp $t$, we can notice that the first block of encrypted password (tokens) are quite similar. They differ on the least significant bytes due to the difference between timestamps. This block is not interesting to retrieve $A$ and $B$.

The second plaintext block $p_1$ is xored with $A \times t + B \mod 2^{32}$.
This is very intersting.


We will write this down for the two tokens we obtained, focusing on the second block.

$C1_1$ : second block of the first token obtained

$t_1$: first timestamps obtained

$C1_2$ : second block  of the second token obtained

$t_2$: second timestamps obtained

$P$: password

$C1_1 = P \oplus (A \times t_1 + B \mod 2^{32})$

$C1_2 = P \oplus (A \times t_2 + B \mod 2^{32})$

This leads to:

$C1_1 \oplus P = A \times t_1 + B \mod 2^{32} $

$C1_2 \oplus P = A \times t_2 + B \mod 2^{32} $

Finally: 

$C1_2 \oplus P - C1_1 \oplus P = A \times (t_2 - t_1) \mod 2^{32} $

$ A = (C1_2 \oplus P - C1_1 \oplus P) \times (t_2-t_1)^{-1} \mod 2^{32}$

We know $C1_2$, $C1_1$, $t2$, $t1$ and the first 16 bits of $P$ which are "n:".

By brute forcing the remaining 16 bits of P, we will obtain an A, compute $B$ and a key candidate. 

$B$ can be computed as follow:

$B = C1_1 \oplus P - A \times t_1 \mod 2^{32}$

Finally We can use the _proof_ to validate $A$, $B$ and the password obtain by the decryption.

Here is the password, $A$ and $B$
```
FOUND: b'ph0wn:AiZAEU7VlRWfJLDUpN9' 453241746 1462504568
```
The script is available [here](https://github.com/0xbaaf/ph0wn-2021/blob/main/lucrative_1/solution/attack.py "attack.py").

The last step of the challenge was to use Wendel credential to log into the central server and get the flag.
