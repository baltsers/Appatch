import time
import os
import random
random.seed(1000)

import anthropic



#f=open('exemplars_rea.txt')
#exemplars=f.read()
#f.close()

#f=open('vulnerable_slices.txt')
#slice_text=f.read()
#f.close()

#f=open('zeroday_0229_slices.txt')
#slice_text=f.read()
#f.close()
#slices=slice_text.split('====================\n')
#testing_slices=slices

f=open('zeroday_interprocedural_slices_revision.txt')
slice_text=f.read()
f.close()
slices=slice_text.split('====================\n')
testing_slices=slices


f=open('zeroday_interprocedural_vullines_revision.txt')
vul_lines=f.readlines()
f.close()
vul_line_loc={}
for vul_line in vul_lines:
    try:
        vul_line_loc[vul_line.split(':')[0]]=int(vul_line[:-1].split(':')[1])
    except:
        pass




#slices=slice_text.split('====================\n')
#random.shuffle(slices)
#training_slices=slices[:200]
#testing_slices=slices[200:]

#fres=open('multi_valid.res','w')

for i, testing_slicex in enumerate(testing_slices):
    if i<0:
        continue
    #try:
    pair=testing_slicex.split('_vul.c')[0]
    #if not 'get_bitmap_file' in pair:
    #    continue
    #print(pair)
    parts=pair.split('_')
    cwe=''
    for part in parts:
        if 'CWE-' in part:
            if 'noinfo' in part or 'Other' in part:
                break
            cwe=part
            break
    #cwe=CWE_map[cwe]
    f=open('./zeroday_0229_repair_usenix_revision/'+pair+'/vul.c')
    code_lines=f.readlines()
    f.close()
    slice_code=''
    for j, code_line in enumerate(code_lines):
        slice_code=slice_code+str(j+1)+' '+code_line
    '''
    try:
        slice_code=testing_slicex[:-2].split('_vul.c\n')[1]
    except:
        continue
    f=open('./zeroday_0229_repair_usenix/'+pair+'/vul.c')
    code_lines=f.readlines()
    f.close()
    if 'CWE-416' in pair:
        slice_code=''
        for j, code_line in enumerate(code_lines):
            slice_code=slice_code+str(j+1)+' '+code_line
    '''
    vulnerable_line=str(vul_line_loc[pair+'_vul.c'])+' '+code_lines[vul_line_loc[pair+'_vul.c']-1]
    
    p=os.popen('diff ./zeroday_0229_repair_usenix_revision/'+pair+'/vul.c ./zeroday_0229_repair_usenix_revision/'+pair+'/nonvul.c')
    patch_lines=p.readlines()
    gth_patch=''
    before_line=''
    after_line=''
    if 'a' in patch_lines[0]:
        before_line_idx=int(patch_lines[0].split('a')[0])
        before_line=code_lines[before_line_idx-1]
        after_line=code_lines[before_line_idx]
    if 'a' in patch_lines[0]:
        gth_patch=gth_patch+'< '+before_line+'< '+after_line+'---\n'
        gth_patch=gth_patch+'> '+before_line
    for patch_line in patch_lines[1:]:
        gth_patch=gth_patch+patch_line
    if 'a' in patch_lines[0]:
        gth_patch=gth_patch+'> '+after_line
    prompt=''
    for code_line in code_lines:
        if code_line[:-1] in gth_patch.split('\n')[0]:
            break
        prompt=prompt+code_line
    prompt=prompt+'/* fixed '+cwe+' vulnerability*/\n'+'Please provide five possible code completion.'
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
    f=open('./patch_s2_multi_claude3_usenix_revision/'+pair+'_'+str(0)+'.txt','w')
    f.write(response)
    f.close()
    print(response)
    time.sleep(3)
    #except:
        #pass
#fres.close()
    
