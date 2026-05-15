import time
import os
import random
random.seed(1000)

import anthropic

f=open('zeroday_interprocedural_slices_revision.txt')
slice_text=f.read()
f.close()
slices=slice_text.split('====================\n')
testing_slices=slices


f=open('vulnerable_slices.txt')
slice_text=f.read()
f.close()
slices=slice_text.split('====================\n')
random.shuffle(slices)
training_slices=slices#[:200]

f=open('zeroday_interprocedural_vullines_revision.txt')
vul_lines=f.readlines()
f.close()
vul_line_loc={}
for vul_line in vul_lines:
    try:
        vul_line_loc[vul_line.split(':')[0]]=int(vul_line[:-1].split(':')[1])
    except:
        pass


f=open('patchdb_cvefixes_vullines.txt')
vul_lines=f.readlines()
f.close()
vul_line_loc_train={}
for vul_line in vul_lines:
    try:
        vul_line_loc_train[vul_line.split(':')[0]]=int(vul_line[:-1].split(':')[1])
    except:
        pass





for i, testing_slicex in enumerate(testing_slices):
    if i<0:
        continue
    for jjj in range(1):
        print(i)
        pair=testing_slicex.split('_vul.c')[0]
        parts=pair.split('___')
        cwe=''
        for part in parts:
            if 'CWE-' in part:
                if 'noinfo' in part or 'Other' in part:
                    break
                cwe=part
                break
        f=open('./reasonings_rea_exemplars_prog_usenix_revision_claude3_code/'+pair)
        slice_code=f.read()
        f.close()
        for slice_line in slice_code.split('\n'):
            if str(vul_line_loc[pair+'_vul.c']) in slice_line[:3]:
                vulnerable_line=slice_line
                break
        
        if not cwe in CWEs:
            CWEs[cwe]=1
        else:
            CWEs[cwe]+=1
        
        f=open('./reasonings_rea_exemplars_prog_usenix_revision_claude3/'+pair+'_0.txt')
        root_cause=f.read()
        f.close()
        exemplars=''
        train_count=0
        random.shuffle(training_slices)
        if os.path.exists('./patch_with_dyn_exemplars_prog_multi_usenix/'+pair+'_'+str(jjj)+'.txt'):
            continue
        
        for j,training_slicex in enumerate(training_slices):
            train_pair=training_slicex.split('_vul.c')[0]
            parts=train_pair.split('_')
            train_cwe=''
            for part in parts:
                if 'CWE-' in part:
                    if 'noinfo' in part or 'Other' in part:
                        break
                    train_cwe=part
                    break
            if train_cwe=='CWE-401':
                train_cwe='CWE-416'
            if not train_cwe == cwe:
                continue
            try:
                train_slice_code=training_slicex[:-2].split('_vul.c\n')[1]
                f=open('./patchdb_cvefixes_for_appatch/'+train_pair+'/'+train_pair+'_vul.c')
                train_code_lines=f.readlines()
                f.close()
            except:
                continue
            if 'CWE-416' in train_pair:
                train_slice_code=''
                for j, code_line in enumerate(train_code_lines):
                    train_slice_code=train_slice_code+str(j+1)+' '+code_line
            train_vulnerable_line=str(vul_line_loc_train[train_pair])+' '+train_code_lines[vul_line_loc_train[train_pair]-1]
            try:
                f=open('./reasonings_claude3_usenix/'+train_pair+'_0.txt')
                exemplar_ans=f.read()
                f.close()
                train_cause=exemplar_ans.split('Step 1: ')[1].split('Step 2')[0]
            except:
                continue
            prompt='Q: Does the following two vulnerabilities share similar root causes?\n"""\n'+train_cause+'\n"""\n\n"""\n'+root_cause[3:]+'\n"""\nPlease simply answer yes or no.'
            print(prompt)
            message = client.messages.create(
                    model="claude-3-5-sonnet-20240620",
                    max_tokens=2000,
                    temperature=0.0,
                    system="Please strictly follow the formats in the provided exemplars.",
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
            response=message.content[0].text
            print(response)
            if not 'Yes' in response:
                continue
            exemplars=exemplars+"\n\n\nQ: Given the following code slice:\n```\n"+train_slice_code+"```\nwhich has a "+cwe+" vulnerability at line:\n```\n"+train_vulnerable_line+"```\nPlease generate the patch for the vulnerability.\n"+exemplar_ans
            train_count+=1
            if train_count>3:
                break
        

        prompt=exemplars+"\n\n\nQ: Given the following code slice:\n```\n"+slice_code+"```\nwhich has a "+cwe+" vulnerability at line:\n```\n"+vulnerable_line+"```\nPlease generate five possible patches for the vulnerability.\nA: The patch can be done in two steps.\nStep 1. "+root_cause[3:]
        print(prompt)
        print(i,pair,jjj)
        #import pdb
        #pdb.set_trace()
        message = client.messages.create(
                    model="claude-3-5-sonnet-20240620",
                    max_tokens=2000,
                    temperature=0.0,
                    system="Please strictly follow the formats in the provided exemplars.",
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
        response=message.content[0].text
        f=open('./patch_with_dyn_exemplars_prog_multi_usenix_revision_claude3/'+pair+'_'+str(jjj)+'.txt','w')
        f.write("Step 1: "+root_cause[3:]+'\n'+response)
        f.close()
        f=open('./patch_with_dyn_exemplars_prog_multi_usenix_revision_claude3_prompts/'+pair+'_'+str(jjj)+'.txt','w')
        f.write(prompt)
        f.close()
        
        print(response)
        
