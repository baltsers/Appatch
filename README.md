# Appatch

**Appatch: Automated Adaptive Prompting Large Language Models for Real-World Software Vulnerability Patching**

| | |
|---|---|
| Original artifact | <https://zenodo.org/records/14736631> |
| Imported from | the publications page |
| Tool | `pubs2github` |


---

## Contents

The artifact contains 2 file(s), primarily Documentation.

```
├── appatch.zip
└── README.md
```

---

## Original `README.md` (from the upstream artifact)

# APPATCH: Automated Adaptive Prompting Large Language Models for Real-World Software Vulnerability Patching
To elicit LLMs to effectively reason about vulnerable code behaviors, which is essential for quality patch generation, we introduce vulnerability semantics reasoning and adaptive prompting on LLMs and instantiate the methodology as APPATCH, an automated LLM-based patching system.

## How to use

To run a functional APPATCH, we provide a Docker image with automatic scripts to execute the key inference components described in the paper, including *Semantics-Aware Scoping (Slicing)*, *Vulnerability Semantics Reasoning (Root Cause Analysis)*, *Dynamic Adaptive Prompting (Patch Generation)*, and *Multi-Faceted Patch Validation*. Please find the **Setup** and **Usage** below to install the image and execute the artifact.

For the datasets and results, please download **appatch.zip** and use the **Package Structure** below to find the corresponding contents described in the original paper. 

## Setup

### Requirements

Hardware:
- \>= 20GB hardware disk space
- \>= 16GB CPU memory

Software:
- Docker

### Install
We have uploaded the functional Docker image to Docker hub. To pull and run the image, simply run:

> docker run -it -d --name appatch-demo g2ecb/appatch-demo bash

After installing the image, enter the container with:

> docker exec -it appatch-demo bash

## Usage

We provide a script to run the key components as a whole. However, since APPATCH depends on commercial LLMs, you need to first provide the API keys for Anthropic (Claude3),  OpenAI (GPT), Google (Gemini), and Groq (Llama3). 

Besides, considering the high cost of the commercial LLMs, we only provide 16 interprocedural samples for the demo. For the complete datasets and results, please refer to **appatch.zip** below.

After entering the Docker container, please first provide the keys above in the **api_keys.json** file.

> cd ~ 

> vi api_keys.json

Then, execute the script to run the whole pipeline:

> source run_demo.sh

After running the pipeline, the generated slices, root cause analysis, patches, and validation results are stored in **interprocedural_sample_slices**, **root_cause_analysis**, **generated_patches**, and **generated_patches_<model-name>_valid**.


## Package Structure
- `appatch.zip`: The datasets and results for the Appatch.
    - `dataset`: The dataset we collected, labeled, and for evaluating Appatch.
        - `patchdb_cvefixes_for_appatch_train`: The PatchDB+CVEFixes dataset used to generate exemplars for Appatch.
        - `zeroday_repair`: The zeroday dataset we collected for evaluation.
        - `extractfix_dataset`: The extractfix dataset we used for evaluation.
    - `results`: The results of Appatch, baselines, and the ablation studies
        - `claude3`: The results of Appatch and ablation studies using Claude 3.5 Sonnet.
            - `appatch`: The results of Appatch.
                - `zeroday`: The exemplars, generated root causes, prompts, generated patches, validations, and results for zeroday dataset.
                - `interprocedural`: The generated root causes, prompts, generated patches, validations, and results for interprocedural samples.
                - `extractfix`: The generated root causes, prompts, generated patches, validations, and results for extractfix dataset.
            - `noslice`: The results of Appatch without slicing with the same format as `appatch`.
            - `rand_exemplars`: The results of Appatch with random exemplars with the same format as `appatch`.
            - `fixed_exemplars`: The results of Appatch with manual exemplars with the same format as `appatch`.
            - `standard prompting`: The results of Appatch with direct reasoning with the same format as `appatch`.
            - `zero`: The results with standard prompting.
            - `s2`: The results with zero-shot completion.
            - `codeql_appatch`: The results of Appatch with CodeQL end-to-end experiments (fully automated).
            - `codeql_human_appatch`: The results of Appatch with CodeQL end-to-end experiments (realistic).
        - `gpt4`: The results of Appatch and ablation studies using GPT-4 with the same format as `claude3`.
        - `gemini`: The results of Appatch and ablation studies using Gemini 1.5 Pro with the same format as `claude3`.
        - `llama3`: The results of Appatch and ablation studies using Llama 3.1 with the same format as `claude3`.
        - `vulrepair`: The results of the baseline VulRepair.
        - `getafix`: The results of the baseline Getafix.
        - `codellama`: The results of Appatch using CodeLlama.
        - `codeqwen`: The results of Appatch using CodeQwen 1.5.
        - `deepseek-coder2`: The results of Appatch using DeepSeek-Coder-V2.
    - `code`: The source code for Appatch, ablated versions, baselines, as well as the usability experiments.
        - `appatch_ablated`: The source code for Appatch and its ablated versions. Switch to the LLMs you want to test and fill your keys when using them.
        - `baselines`: The source code for the traditional baselines we compared.
        - `usability_codeql`: The source code for the usability experiments with CodeQL.


## Semantics-Aware Scoping

We also implemented the semantics-aware scoping based on SySeVR. To reuse this part, please use the following commands set up the vulnerability-semantics scoping module:

> docker run -it -d --name vulnerability-slicing g2ecb/vulnerability-slicing bash

> docker exec -it vulnerability-slicing bash

Check the instructions in ~/run_all.sh and run the command:

> source run_all.sh

The generated slice can be found in ~/source2slice/C/test_data/4/vulnerable_slices.txt



