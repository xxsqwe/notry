# Artifact Appendix

Paper title: **NOTRY: Deniable messaging with retroactive avowal**

Artifacts HotCRP Id: **#8**

Requested Badge: **Reproducible**

## Description
This artifact is designed to see the performance of our novel key exchange primitive compared with Signal.

### Security/Privacy Issues and Ethical Concerns
No

## Basic Requirements
Anything but Apple Macbook m1/m2

### Hardware Requirements
No.

### Software Requirements
Tested on MacOs and Ubuntu 22.04.
Rust version should be nightly-2022-06-22


### Estimated Time and Storage Consumption
Maxium few minutes, hundreds of MB storage after compilation

## Environment
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly-2022-06-22
rustup default nightly-2022-06-22

pip3 install matplotlib

### Accessibility
https://github.com/xxsqwe/notry main branch


### Set up the environment
git clone --recurse-submodules https://github.com/xxsqwe/notry.git




### Testing the Environment

cd notry

cargo test
## Artifact Evaluation
./run.sh


### Main Results and Claims
Our implementation incurs roughly 8× communication and computation overhead over
the standard Signal protocol during regular operation. We find it
is nonetheless deployable in a realistic setting as key exchanges
(the source of the overhead) still complete in just over 1ms on a
modern computer. The avowal protocol induces only constant computation and communication performance for the communicating
parties and scales linearly in the number of messages avowed for
the verifier—in the tens of milliseconds per avowal.
#### Main Result 1: Key exchange
Section 6.1, 2nd paragraph

We implement NOTRY and evaluate its performance. In comparison to Signal, clients incur an 8× times communication overhead and an 8× times computational overhead
per key exchange — a manageable performance hit in the face
of likely future improvements. When parties wish to avow a
message, both they and the judge pay further computation
and communication costs to run the avowal protocol.

#### Main Result 2: Avowal
Section 6.1, 3rd and 4th paragraph.

We further show that our avowal protocol scales effectively
to an entire transcript. Parties are free to avow a stream
of messages in a conversation without incurring communication overhead above that of avowing a single message.
They only need to operate an extra scalar addition for each
additional message avowal. The computation and communication performance overhead of the designated verifier
grows linearly with the number of messages to be avowed
for the verifier, with the slope of 0.006 for computation and
receiving extra 32 bytes each time for avowing one more
message.

### Experiments
List each experiment the reviewer has to execute. Describe:
 - How to execute it in detailed steps. ./run.sh
 - What the expected result is. A plotted figure and a log file named performance
 - How long it takes and how much space it consumes on disk. (approximately) within 10mins, within 1GB
 - Which claim and results does it support, and how. Table 1 and Figure 7

#### Experiment 1: Name

#### Experiment 2: Name
...

#### Experiment 3: Name
...

## Limitations


## Notes on Reusability
First, this section might not apply to your artifacts.
Use it to share information on how your artifact can be used beyond your research paper, e.g., as a general framework.
The overall goal of artifact evaluation is not only to reproduce and verify your research but also to help other researchers to re-use and improve on your artifacts.
Please describe how your artifacts can be adapted to other settings, e.g., more input dimensions, other datasets, and other behavior, through replacing individual modules and functionality or running more iterations of a specific part.