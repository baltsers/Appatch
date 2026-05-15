import time
import os
import random
random.seed(1000)

import anthropic




#f=open('exemplars_rea.txt')
#exemplars=f.read()
#f.close()


'''
f=open('zeroday_0229_slices.txt')
slice_text=f.read()
f.close()
'''
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

'''
f=open('zeroday_0229_vullines.txt')
vul_lines=f.readlines()
f.close()
'''
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


CWEs={}
'''
CWE_map={'CWE-119':'CWE-119', 'CWE-120':'CWE-119', 'CWE-125':'CWE-119', 'CWE-787':'CWE-119', 
            'CWE-191':'CWE-682', 'CWE-190':'CWE-682', 'CWE-189':'CWE-682', 'CWE-682':'CWE-682', 'CWE-369':'CWE-682', 'CWE-193':'CWE-682',
            'CWE-200':'CWE-264', 'CWE-284':'CWE-264', 'CWE-264':'CWE-264',
            'CWE-908':'CWE-399', 'CWE-362':'CWE-399', 'CWE-665':'CWE-399', 'CWE-19':'CWE-399','CWE-399':'CWE-399',
            'CWE-59':'CWE-20', 'CWE-20':'CWE-20', 'CWE-89':'CWE-20', 'CWE-78':'CWE-20',
            'CWE-415':'CWE-465', 'CWE-476':'CWE-465', 'CWE-416':'CWE-465',
            '':''
            }
'''





for i, testing_slicex in enumerate(testing_slices):
    if i<0:
        continue
    for jjj in range(1):
        print(i)
        #try:
        pair=testing_slicex.split('_vul.c')[0]
        #if not '24188' in pair:
        #    continue
        #print(pair)
        parts=pair.split('___')
        cwe=''
        for part in parts:
            if 'CWE-' in part:
                if 'noinfo' in part or 'Other' in part:
                    break
                cwe=part
                break
        #cwe=CWE_map[cwe]
        #try:
        #slice_code=testing_slicex[:-2].split('_vul.c\n')[1]
        #except:
        #    continue
        f=open('./reasonings_rea_exemplars_prog_usenix_revision_claude3_code/'+pair)
        slice_code=f.read()
        f.close()
        for slice_line in slice_code.split('\n'):
            if str(vul_line_loc[pair+'_vul.c']) in slice_line[:3]:
                vulnerable_line=slice_line
                break
        '''
        f=open('./zeroday_0229_vul/'+pair+'_vul.c')
        code_lines=f.readlines()
        f.close()
        if 'CWE-416' in pair:
            slice_code=''
            for j, code_line in enumerate(code_lines):
                slice_code=slice_code+str(j+1)+' '+code_line
        vulnerable_line=str(vul_line_loc[pair+'_vul.c'])+' '+code_lines[vul_line_loc[pair+'_vul.c']-1]
        
        p=os.popen('diff ./patchdb_cvefixes_for_appatch/'+pair+'/'+pair+'___vul.c ./patchdb_cvefixes_for_appatch/'+pair+'/'+pair+'_nonvul.c')
        patch_lines=p.readlines()
        patch=''
        before_line=''
        after_line=''
        if 'a' in patch_lines[0]:
            before_line_idx=int(patch_lines[0].split('a')[0])
            before_line=code_lines[before_line_idx-1]
            after_line=code_lines[before_line_idx]
        if 'a' in patch_lines[0]:
            patch=patch+'< '+before_line+'< '+after_line+'---\n'
            patch=patch+'> '+before_line
        for patch_line in patch_lines[1:]:
            patch=patch+patch_line
        if 'a' in patch_lines[0]:
            patch=patch+'> '+after_line
        '''

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
            #if not train_cwe == cwe:
            #    continue
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
            '''
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
            '''
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
        f=open('./patch_with_dyn_exemplars_prog_multi_rand_usenix_revision_claude3/'+pair+'_'+str(jjj)+'.txt','w')
        f.write("Step 1: "+root_cause[3:]+'\n'+response)
        f.close()
        f=open('./patch_with_dyn_exemplars_prog_multi_rand_usenix_revision_claude3_prompts/'+pair+'_'+str(jjj)+'.txt','w')
        f.write(prompt)
        f.close()
        
        print(response)
        #time.sleep(3)
        #except:
        #    pass
    #import pdb
    #pdb.set_trace()

