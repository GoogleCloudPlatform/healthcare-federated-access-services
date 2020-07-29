# GA4GH Passports

## Use of Cloud

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/bring_compute_to_data.svg">

Instead of downloading data for local compute analysis, researchers may bring
their compute jobs to the cloud to work on the data directly.
*  **Data Remains in Place**: once the Data Controller publishes one or more
   copies of the data for researchers to use, the data no longer needs to be
   downloaded outside those cloud environments in order to do analysis.
*  **Compute Jobs move to Cloud**: instead of data moving to a local researcher
   compute node, a researcher leveraging cloud compute moves the compute job's
   configurations to run near the data center hosting one or more of the copies
   in the cloud.

## Benefits of Cloud

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/benefits_of_cloud.svg">

1. **Security Improvements**: By bringing compute jobs to execute on the data
   in place, there is visibility to the Data Controller on how the data is being
   used.
   *  Avoids unmanaged downloads where access controls are unknown.
   *  Having unmanaged downloads increases the attack surface for viruses and
      hackers to compromise security measures. The cloud approach can limit
      this risk and unsure a consistent, managed approach under the Data
      Controller's coordination.
   *  Access to data has a consistent means to provide Data Controllers's with
      a full set of audit logs to investigate anomalies and put extra data
      governance monitoring in place.

1. **Regulation**: Downloading to where a researcher's compute resources are
   available does not always meet regulatory compliance requirements.
   *  Some PHI data has geolocation storage and processing requirements that
      do not allow the data to leave a particular geographic region.
   *  Other regulations may require a level of oversight over the data that
      unmanaged downloads does not comply with.

1. **Use Data in Place**: There are additional benefits to using data in place
   that are not already captured by the benefits above.
   *  Some data downloads will envoke network egress charges to move large
      amounts of data to the local compute node. These costs can be significant
      and reduce the budget available for biomedical analysis.
   *  Downloading and setting up a local copy of the data may be time consuming.
      In some cases, this can consume up to 30% of the research time that could
      have otherwise been available for analysis.

1. **Cloud Scale**: Reuse of shared compute hardware on demand puts the entire
   project's compute budget being used for analysis instead of long-term
   hardware ownership.
   *  Allows more compute to be available within a project's budget, thus
      providing for deeper and extended analysis.
   *  Allows analysis to complete faster by leveraging large pools of hardware
      that execute in parallel, yielding quicker turn-around. This gives more
      time and focus on iterations for better tuning and discovery insights.

1. **Advanced Tools**: Cloud has the ability to completely revolutionize
   research by providing best-of-breed research tools at cloud scale that are
   not available on systems within individual research labs.
   *  **Big Data** tools allow Clouds to process millions of individual records
      per second to bring scale and detail of analysis to a whole new level.
      These tools alone have the potiential to make Principal Investigators
      three times more effective with their research when compared to
      traditional analysis methods.
   *  **Machine Learning** and **Artificial Intelligence** are the next wave of
      tools that will help discover corrolations between data that were not
      possible to see using traditional approaches.
   *  Cloud infrastructure providers are not only investing in providing
      hardware and storage, but are constantly innovating on these advanced
      tools to make them leading-edge. This allows researchers to focus on their
      research while infrastructure providers build the tools for researchers to
      use, which accelerates the entire process.

## Challenges

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/challenges_of_cloud.svg" width="700px">

## Solution

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/passports_flow.svg">

## Benefits of Passports

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/benefits_of_passports.svg" width="700px">
