from queue import Queue
from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
from threading import Thread
import time
import boto3
import logging
import csv

# Queues
profile_queue = Queue()
iam_entity_queue = Queue()
report_gen_job_queue = Queue()
report_output_queue = Queue()

# Logging
logger =logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

# AWS Configuration to escape throttling
config = Config(
   retries = {
                'max_attempts': 10,
                'mode': 'adaptive'
   }
)

# Flags
iam_entity_query_complete = False
iam_entity_report_gen_complete = False
iam_entity_report_get_complete = False

def get_iam_entities_arns():
    global profile_queue
    global iam_entity_queue
    global config

    while not profile_queue.empty():
        profile = profile_queue.get()
        session = boto3.Session(profile_name=profile)
        iam_client = session.client('iam', config=config)

        response = None
        marker = None
        while response is None or response.get('IsTruncated'):
            try:
                if marker is None:
                    response = iam_client.get_account_authorization_details()
                else:
                    response = iam_client.get_account_authorization_details(Marker=marker)

                users = response.get('UserDetailList')
                roles = response.get('RoleDetailList')
                # groups = response.get('GroupDetailList')
                # policies = response.get('Policies')
                if users:
                    for user in users:
                        iam_entity_queue.put({'arn': user['Arn'],
                                              'entity_type': 'User',
                                              'profile': profile,
                                              'iam_client': iam_client})

                if roles:
                    for role in roles:
                        iam_entity_queue.put({'arn': role['Arn'],
                                              'entity_type': 'Role',
                                              'profile': profile,
                                              'iam_client': iam_client})

                # if groups:
                #     for group in groups:
                #         iam_entity_queue.put({'arn': group['Arn'],
                #                               'entity_type': 'Group',
                #                               'profile': profile,
                #                               'iam_client': iam_client})
                #
                # if policies:
                #     for policy in policies:
                #         iam_entity_queue.put({'arn': policy['Arn'],
                #                               'entity_type': 'Policy',
                #                               'profile': profile,
                #                               'iam_client': iam_client})

                if response['IsTruncated']:
                    marker = response['Marker']
            except awsClientError as error:
                if error.response['Error']['Code'] in [ "RequestTimeout",
                                                        "RequestTimeoutException",
                                                        "PriorRequestNotComplete",
                                                        "ConnectionError",
                                                        "HTTPClientError",
                                                        "Throttling",
                                                        "ThrottlingException",
                                                        "ThrottledException",
                                                        "RequestThrottledException",
                                                        "TooManyRequestsException",
                                                        "ProvisionedThroughputExceededException",
                                                        "TransactionInProgressException",
                                                        "RequestLimitExceeded",
                                                        "BandwidthLimitExceeded",
                                                        "LimitExceededException",
                                                        "RequestThrottled",
                                                        "SlowDown",
                                                        "EC2ThrottledException"]:
                    logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                    time.sleep(20)
                else:
                    logger.error("Encountered Error: {} !! Exiting .. ".format(error.response['Error']['Code']))
                    return
        profile_queue.task_done()
        logger.info("IAM entity query for profile {} done!!".format(profile))
    logger.info("No more profiles to process !!")


def generate_access_advisor_report():
    global iam_entity_queue
    global report_gen_job_queue
    global iam_entity_query_complete

    while True:
        if iam_entity_query_complete and iam_entity_queue.empty():
            logger.info("IAM entity query is complete and IAM entity queue is empty, I am done :) !!")
            break
        else:
            logger.debug("Starting to work on report generation !!")
            while not iam_entity_queue.empty():
                job_id = None
                iam_entity_arn_detail = iam_entity_queue.get()
                iam_client = iam_entity_arn_detail['iam_client']
                arn = iam_entity_arn_detail['arn']
                while job_id is None:
                    try:
                        job_id = iam_client.generate_service_last_accessed_details(Arn=arn).get('JobId')
                        logger.debug("Report generated with job id {} for arn {} and profile {}".format(job_id, arn, iam_entity_arn_detail['profile']))
                        report_gen_job_queue.put({ 'job_id': job_id,
                                                   'arn': arn,
                                                   'iam_client' : iam_client,
                                                   'entity_type' : iam_entity_arn_detail['entity_type'],
                                                   'profile' : iam_entity_arn_detail['profile']
                                                })
                        break
                    except awsClientError as error:
                        if error.response['Error']['Code'] in [ "RequestTimeout",
                                                                "RequestTimeoutException",
                                                                "PriorRequestNotComplete",
                                                                "ConnectionError",
                                                                "HTTPClientError",
                                                                "Throttling",
                                                                "ThrottlingException",
                                                                "ThrottledException",
                                                                "RequestThrottledException",
                                                                "TooManyRequestsException",
                                                                "ProvisionedThroughputExceededException",
                                                                "TransactionInProgressException",
                                                                "RequestLimitExceeded",
                                                                "BandwidthLimitExceeded",
                                                                "LimitExceededException",
                                                                "RequestThrottled",
                                                                "SlowDown",
                                                                "EC2ThrottledException"]:
                            logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                            time.sleep(20)
                        else:
                            logger.error("Encountered Error: {} !! Exiting .. ".format(error.response['Error']['Code']))
                            return

                iam_entity_queue.task_done()
                logger.debug("Report generation for IAM entity {} from profile {} completed.".format(arn, iam_entity_arn_detail['profile']))

            # Sleeping for 10 seconds until IAM entities fill up
            logger.debug("IAM entity queue is empty and iam entity query worker(s) is/are running , going to sleep !!")
            time.sleep(10)

def get_access_advisor_report():
    global report_gen_job_queue
    global report_output_queue
    global iam_entity_report_gen_complete
    global iam_entity_queue

    while True:
        if iam_entity_report_gen_complete and report_gen_job_queue.empty():
            logger.info("IAM entity report generation is complete and IAM entity report generation queue is empty, I am done :) !!")
            break
        else:
            while not report_gen_job_queue.empty():
                logger.debug("Starting to work on getting the report !!")
                report_gen_detail = report_gen_job_queue.get()
                iam_client = report_gen_detail['iam_client']
                job_id = report_gen_detail['job_id']

                response = None
                marker = None
                report = dict()
                report['ServicesLastAccessed'] = []

                while response is None or response.get('IsTruncated'):

                    if marker is None:
                        response = iam_client.get_service_last_accessed_details(JobId=job_id)
                    else:
                        response = iam_client.get_service_last_accessed_details(JobId=job_id, Marker=marker)

                    if response.get('JobStatus') == "FAILED" or response.get('Error'):
                        # If report fails , this will add it up as a new task for generating a new report
                        logger.warning("Report Generation job {} for arn {} and profile {} failed or met with an error. "
                                       "IAM entity pushed to queue for report regeneration".format(job_id,
                                                                                                   report_gen_detail['arn'],
                                                                                                   report_gen_detail['profile']))
                        iam_entity_queue.put({'arn': report_gen_detail['arn'],
                                              'entity_type': report_gen_detail['entity_type'],
                                              'profile': report_gen_detail['profile'],
                                              'iam_client': iam_client})
                        break

                    if response.get('JobStatus') == "COMPLETED":
                        if response.get('IsTruncated'):
                            marker = response.get('Marker')
                            report['ServicesLastAccessed'] += response['ServicesLastAccessed']
                        else:
                            report['ServicesLastAccessed'] = response['ServicesLastAccessed']

                    else:
                        # Waiting for the report to complete
                        time.sleep(5)
                report_output_queue.put({'arn': report_gen_detail['arn'],
                                          'entity_type': report_gen_detail['entity_type'],
                                          'profile': report_gen_detail['profile'],
                                           'access_advisor_report' : report['ServicesLastAccessed']
                                         })
                report_gen_job_queue.task_done()
                logger.debug("Report Output for IAM entity {} from profile {} completed.".format(report_gen_detail['arn'],
                                                                                                report_gen_detail['profile']))

            # Sleeping for 10 seconds until report generation job fills up
            logger.debug("IAM entity report generation queue is empty and IAM entity report generation worker(s) is/are running , going to sleep !!")
            time.sleep(10)

def write_file(file_output=None):
    global report_output_queue
    global iam_entity_report_get_complete

    out = open(file_output, 'w')
    csv_columns = ['Account',
                   'AccountType',
                   'Arn',
                   'EntityType',
                   'ServiceName',
                   'ServiceNamespace',
                   'LastAuthenticated',
                   'LastAuthenticatedRegion',
                   #'LastAuthenticatedEntity',
                   #'TotalAuthenticatedEntities'
                   ]
    writer = csv.DictWriter(out, fieldnames=csv_columns)
    writer.writeheader()

    while True:
        if iam_entity_report_get_complete and report_output_queue.empty():
            logger.info("All report has been taken and queue is empty, I am done :) !!")
            break
        else:
            while not report_output_queue.empty():
                logger.info("Report output queue is not empty, Starting to work !!")
                record = report_output_queue.get()
                if record['profile'].lower().__contains__("staging"):
                    account_type = "Non-Production"
                else:
                    account_type = "Production"

                if record['access_advisor_report']:
                    for service in record['access_advisor_report']:

                        writer.writerow({'Account': record['profile'],
                                         'AccountType': account_type,
                                         'Arn': record['arn'],
                                         'EntityType': record['entity_type'],
                                         'ServiceName': service.get('ServiceName'),
                                         'ServiceNamespace': service.get('ServiceNamespace'),
                                         'LastAuthenticated': service.get('LastAuthenticated'),
                                         'LastAuthenticatedRegion': service.get('LastAuthenticatedRegion'),
                                        #'LastAuthenticatedEntity': service.get('LastAuthenticatedEntity'),
                                        #'TotalAuthenticatedEntities': service.get('TotalAuthenticatedEntities')
                                         })
                else:
                    writer.writerow({'Account': record['profile'],
                                     'AccountType': account_type,
                                     'Arn': record['arn'],
                                     'EntityType': record['entity_type'],
                                     'ServiceName': None,
                                     'ServiceNamespace': None,
                                     'LastAuthenticated': None,
                                     'LastAuthenticatedRegion': None,
                                     #'LastAuthenticatedEntity': None,
                                     #'TotalAuthenticatedEntities': None
                                     })

                report_output_queue.task_done()
                logger.info("Entry recorded for arn {} from profile {}".format(record['arn'],
                                                                               record['profile']))
            # Sleeping for 10 seconds until report generation job fills up
            logger.debug(
                "Report output queue is empty and report getting worker(s) is/are running , going to sleep !!")
            time.sleep(10)
    out.close()

def start(profiles=None, worker_count=None, out_file=None):

    global profile_queue
    global iam_entity_query_complete
    global iam_entity_report_get_complete
    global iam_entity_report_gen_complete

    # List containing all workers or threads
    iam_entity_query_workers = []
    iam_entity_report_gen_workers = []
    iam_entity_report_get_workers = []

    # Load all profiles to profile queue
    logger.info("Pushing all profiles in to profile queue !!")
    for profile in profiles:
        profile_queue.put(profile)
    logger.debug("Completed pushing all profiles in to profile queue !!")

    # Initiate IAM Entity Workers
    logger.info("Initiating workers for IAM Entity querying !! ")
    if len(profiles) == 1:
        worker = Thread(target=get_iam_entities_arns)
        worker.setDaemon(True)
        worker.start()
        iam_entity_query_workers.append(worker)
    else:
        # By default assigning 2 workers for zone
        for each in range(2):
            worker = Thread(target=get_iam_entities_arns)
            worker.setDaemon(True)
            worker.start()
            iam_entity_query_workers.append(worker)
    logger.debug("Completed initiation of  workers for IAM Entity querying !! ")

    # Initiating the Report Generation Workers
    # By default assigning 2 workers for Report Generation
    logger.info("Initiating workers for report generation !! ")
    for each in range(1):
        worker = Thread(target=generate_access_advisor_report)
        worker.setDaemon(True)
        worker.start()
        iam_entity_report_gen_workers.append(worker)
    logger.debug("Completed initiation of workers for report generation !! ")

    # Initiating the Workers for getting the report
    # By default assigning 2 workers for getting the report
    logger.info("Initiating workers for getting the report !! ")
    for each in range(2):
        worker = Thread(target=get_access_advisor_report)
        worker.setDaemon(True)
        worker.start()
        iam_entity_report_get_workers.append(worker)
    logger.debug("Completed initiation of workers for getting the report !! ")


    # Initiate the File writer worker
    logger.info("Initiating worker for file write !! ")
    file_write_worker = Thread(target=write_file, args=(out_file,) )
    file_write_worker.setDaemon(True)
    file_write_worker.start()
    logger.debug("Completed initiating worker for file write !! ")

    # Monitor the workers
    logger.info("Initiating Worker Monitor!! ")
    while True:

        if not iam_entity_query_complete:
            logger.debug("Checking on whether IAM entity query is complete !! ")
            if not (True in [worker.is_alive() for worker in iam_entity_query_workers]):
                # Making all workers join
                [worker.join() for worker in iam_entity_query_workers]
                logger.info("IAM query is complete !! ")
                iam_entity_query_complete = True

        if not iam_entity_report_gen_complete:
            logger.debug("Checking on whether IAM entity report generation is complete !! ")
            if not (True in [worker.is_alive() for worker in iam_entity_report_gen_workers]):
                # Making all workers join
                [worker.join() for worker in iam_entity_report_gen_workers]
                logger.info("IAM report generation is complete !! ")
                iam_entity_report_gen_complete = True

        if not iam_entity_report_get_complete:
            logger.debug("Checking on whether getting IAM entity report is complete !! ")
            if not (True in [worker.is_alive() for worker in iam_entity_report_get_workers]):
                # Making all workers join
                [worker.join() for worker in iam_entity_report_get_workers]
                logger.info("Getting IAM report is complete !! ")
                iam_entity_report_get_complete = True

        if not(iam_entity_query_complete and iam_entity_report_gen_complete and iam_entity_report_get_complete):
            logger.debug("Workers are still busy working !! Going to sleep !! ")
            time.sleep(10)
        else:
            if file_write_worker.is_alive():
                logger.debug("Query Workers are done !! File writing worker is still busy working !! Going to sleep !! ")
                time.sleep(10)
            else:
                logger.info("Operation Complete :) !!")
                break


# Disclaimer
# Ref : https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html#service-last-accessed-reporting-period


if __name__ == "__main__":

    # Argument , profile , workers
    start(profiles=["default"],
          worker_count=None, out_file='output.txt')