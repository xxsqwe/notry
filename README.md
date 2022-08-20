# Imple_notry
To test:
All executable files are generated in target/debug/examples

First generate certs

./gencert

Start coordinator:

./coord localhost

Then Start Bob

./client localhost Bob Alice

Finally, run Alice

./client localhost Alice Bob init