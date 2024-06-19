# Learning questionnaire generation

This pattern generates questions to help a learner/student review the main concepts of the learning objectives provided.

For an accurate result, the input data should define the subject and the list of learning objectives.

Example prompt input:

```txt
# Optional to be defined here or in the context file
[Student Level: High school student]

Subject: Machine Learning

Learning Objectives:
* Define machine learning
* Define unsupervised learning
```

## Example run in bash

Copy the input query to the clipboard and execute the following command:

``` bash
xclip -selection clipboard -o | fabric -sp create_quiz
```
