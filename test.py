import json
import boto3
import os
import sys
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime


app_autoscaling = boto3.client('application-autoscaling')
cloudwatch = boto3.client('cloudwatch')
dynamodb = boto3.client('dynamodb')
appstream = boto3.client('appstream') 


def fleet_desc(policyname,fleetname):
    try:
        fleet_desc = app_autoscaling.describe_scaling_policies(
            PolicyNames=[policyname], 
            ServiceNamespace='appstream',
            ResourceId=fleetname,
            ScalableDimension='appstream:fleet:DesiredCapacity'
        )
    except Exception as exception:
        print("[Warning] Describe Scaling Policy, Error:",exception)
    try:
        alarmname=fleet_desc['ScalingPolicies'][0]['Alarms'][0]['AlarmName']
        print("[Ok] [{}] [{}] Capture Alarm Name".format(fleetname.replace("fleet/",""),policyname))
        return alarmname
    except Exception as exception:
        print("[Fail] [{}] [{}] Capture Alarm Name. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        
        

def describe_alarms(alarmname,fleetname,policyname):
    try:
        alarm_desc=cloudwatch.describe_alarms(AlarmNames=[alarmname])
    except Exception as exception:
        print("[Warning] Describe Alarm, Error:",exception)
    try:
        alarmaction=alarm_desc['MetricAlarms'][0]['AlarmActions'][0]
        print("[Ok] [{}] [{}] Capture Alarm Action".format(fleetname.replace("fleet/",""),policyname))
        return alarmaction
    except Exception as exception:
        print("[Fail] [{}] [{}] Capture Alarm Action. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        
    
    
def switch(arg,fleetname,policyname):
    try:
        switcher = {
            ">=": "GreaterThanOrEqualToThreshold",
            "=>": "GreaterThanOrEqualToThreshold",
            ">": "GreaterThanThreshold",
            "<": "LessThanThreshold",
            "<=": "LessThanOrEqualToThreshold",
            "=<": "LessThanOrEqualToThreshold"
        }
        comparison=switcher[arg]
    except Exception as exception:
        print("[Warning] Translate Comparison Operator, Error:",exception)
    if comparison:
        print("[Ok] [{}] [{}] Translate Comparison Operator".format(fleetname.replace("fleet/",""),policyname))
        return comparison
    else:
        print("[Fail] [{}] [{}] Translate Comparison Operator. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        
    
    
def modify_alarm_in(alarmname,threshhold,alarm_condition,metricname,alarmaction,fleetname,policyname):
    try:
        modify_alarm = cloudwatch.put_metric_alarm(
            AlarmName=alarmname,
            Threshold=int(threshhold),
            EvaluationPeriods=10,
            ComparisonOperator=alarm_condition,
            MetricName=metricname,
            Period=120,
            Namespace="AWS/AppStream",
            Statistic="Average",
            AlarmActions=[alarmaction],
            Dimensions=[
                {
                    'Name': 'Fleet',
                    'Value': fleetname.replace("fleet/","")
                },
            ],            
        )
        print("[Ok] [{}] [{}] Modify Policy Alarm IN".format(fleetname.replace("fleet/",""),policyname))
        return int(modify_alarm['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] [{}] Modify Policy Alarm IN. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        

def modify_alarm_out(alarmname,threshhold,alarm_condition,metricname,alarmaction,fleetname,policyname):
    try:
        modify_alarm = cloudwatch.put_metric_alarm(
            AlarmName=alarmname,
            Threshold=int(threshhold),
            EvaluationPeriods=3,
            ComparisonOperator=alarm_condition,
            MetricName=metricname,
            Period=60,
            Namespace="AWS/AppStream",
            Statistic="Average",
            AlarmActions=[alarmaction],
            Dimensions=[
                {
                    'Name': 'Fleet',
                    'Value': fleetname.replace("fleet/","")
                },
            ],  
        )
        print("[Ok] [{}] [{}] Modify Policy Alarm OUT".format(fleetname.replace("fleet/",""),policyname))
        return int(modify_alarm['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] [{}] Modify Policy Alarm OUT. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        

def modify_policy_in(policyname,fleetname,adjustment):
    try:
        policy_modify = app_autoscaling.put_scaling_policy(
            PolicyName=policyname,
            ServiceNamespace='appstream',
            ResourceId=fleetname,
            PolicyType='StepScaling',
            ScalableDimension='appstream:fleet:DesiredCapacity',
            StepScalingPolicyConfiguration={
                'AdjustmentType': 'ChangeInCapacity',
                'StepAdjustments': [
                    {   
                        
                        'MetricIntervalLowerBound': 0.0,
                        'ScalingAdjustment': int(adjustment)
                    }
                ],
                'Cooldown':360,
                'MetricAggregationType':'Average'
            },
        )  
        print("[Ok] [{}] [{}] Modify Scaling Policy IN".format(fleetname.replace("fleet/",""),policyname))
        return int(policy_modify['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] [{}] Modify Scaling Policy OUT. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        
        
        
def modify_policy_out(policyname,fleetname,adjustment):
    try:
        policy_modify = app_autoscaling.put_scaling_policy(
            PolicyName=policyname,
            ServiceNamespace='appstream',
            ResourceId=fleetname,
            PolicyType='StepScaling',
            ScalableDimension='appstream:fleet:DesiredCapacity',
            StepScalingPolicyConfiguration={
                'AdjustmentType': 'ChangeInCapacity',
                'StepAdjustments': [
                    {
                        'MetricIntervalUpperBound': 0.0,
                        'ScalingAdjustment': int(adjustment)
                    }
                ],
                'Cooldown':120,  
                'MetricAggregationType':'Average'  
            },
        )  
        print("[Ok] [{}] [{}] Modify Scaling Policy OUT".format(fleetname.replace("fleet/",""),policyname))
        return int(policy_modify['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] [{}] Modify Scaling Policy OUT. Error: {}".format(fleetname.replace("fleet/",""),policyname,exception))
        




def modify_capacity(fleetname,mincapacity,maxcapacity):
    try:
        cap_modify = app_autoscaling.register_scalable_target(
            ServiceNamespace='appstream',
            ResourceId=fleetname,
            ScalableDimension='appstream:fleet:DesiredCapacity',
            MinCapacity=int(mincapacity),
            MaxCapacity=int(maxcapacity)
        )  
        print("[Ok] [{}] Modify MaxCapacity and MinCapacity".format(fleetname.replace("fleet/","")))
        return int(cap_modify['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] Modify MaxCapacity and MinCapacity. Error: {}".format(fleetname.replace("fleet/",""),exception))
        
        

def get_scaling_data(tablename,day,time):
    dayandtime=day+"("+time+")"
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(tablename)
        data = table.scan(
            FilterExpression=Key('Day').eq(dayandtime) & Key('Active').eq('True')
        )
        if len(data['Items']) > 0 :
            print("[Ok] Retrieve Data from the Table, Fleet Count:",len(data['Items']))
            return data['Items']
        else:
            print("[Fail] Retrieve Data from the Table, Fleet Count:",len(data['Items']))
    except Exception as exception:
        print("[Warning] Retrieve Data from the Table, Error:",exception)
        
    
    
    
def modify_desired_capacity(fleetname,desired_capacity):  
    try:
        clean_fleetname=fleetname.replace("fleet/","")
        modify_dc = appstream.update_fleet(
            Name=clean_fleetname,
            ComputeCapacity={
                'DesiredInstances': int(desired_capacity)
            }
        )
        print("[Ok] [{}] Modify Desired Capacity".format(clean_fleetname))
        return int(modify_dc['ResponseMetadata']['HTTPStatusCode'])
    except Exception as exception:
        print("[Fail] [{}] Modify Desired Capacity. Error: {}".format(clean_fleetname,exception))
    
    
    





def lambda_handler(event, context):
    time = event.get('time', None)
    day=datetime.today().strftime('%A')
    tablename=os.environ['Table_Name']
    fleets=get_scaling_data(tablename,day,time)
    if fleets:
        for fleet in fleets:
            fleetname="fleet/"+fleet['Fleet_Name']
            maxcapacity=fleet['Maximum_Capacity'] 
            mincapacity=fleet['Minimum_Capacity']
            desired_capacity=fleet['ScaleIn_Threshold']
            modify_capacity(fleetname,mincapacity,maxcapacity)
            #modify_desired_capacity(fleetname,desired_capacity)
            keys = ('ScaleOut_ComparisonOperator', 'ScaleOut_MetricName', 'ScaleOut_Policy_Name', 'ScaleOut_ScalingAdjustment', 'ScaleOut_Threshold')
            scaleout = {k: fleet[k] for k in keys}
            scaleout = {x.replace('ScaleOut_', ''): v  for x, v in scaleout.items()} 
            keys = ('ScaleIn_ComparisonOperator', 'ScaleIn_MetricName', 'ScaleIn_Policy_Name', 'ScaleIn_ScalingAdjustment', 'ScaleIn_Threshold')
            scalein={k: fleet[k] for k in keys}
            scalein = {x.replace('ScaleIn_', ''): v  for x, v in scalein.items()} 
            policies=[scaleout,scalein]
            for p in policies:
                arg=p['ComparisonOperator']
                metricname=p['MetricName']
                policyname=p['Policy_Name']
                adjustment=p['ScalingAdjustment']
                threshhold=p['Threshold']
                alarmname=fleet_desc(policyname,fleetname)
                if alarmname:
                    alarmaction=describe_alarms(alarmname,fleetname,policyname)
                    if alarmaction:
                        alarm_condition=switch(arg,fleetname,policyname)
                        if alarm_condition:
                            if 'in' in policyname:
                                alarm_modify_status_code=modify_alarm_in(alarmname,threshhold,alarm_condition,metricname,alarmaction,fleetname,policyname)
                            elif 'out' in policyname:
                                alarm_modify_status_code=modify_alarm_out(alarmname,threshhold,alarm_condition,metricname,alarmaction,fleetname,policyname)
                            if alarm_modify_status_code == 200:
                                if 'in' in policyname:
                                    modify_policy_in(policyname,fleetname,adjustment)
                                elif 'out' in policyname:
                                    modify_policy_out(policyname,fleetname,adjustment)
 

