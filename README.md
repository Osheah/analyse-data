# analyse-data

programme to analyse data for GMIT Certificate in Cybersecurity - Programmming for Cybersecurity

Code is in Jupyter notebook format

To view the code click on the ipynb file
To download the code download the repo and open it in jupyter notebook by typing 
```jupyter notebook```
 at the command line.
### Structure
The directory structure is as follows
- images - directory to store images that are in the ipynb file (it contains on picture of MACB notation)* 
- analyse-data.ipynb - the main file
- base-rd-01-supertimeline.csv - not uploaded to github but required. This is the file that is analysed in the data and was taken from course material.
- baserd01-filesystem-timeline.csv - not uploaded to github - not required
- LICENSE - GNU GENERAL PUBLIC LICENSE Version
- README.md - This readme file
- gitignore - I've set the gitignore to ignore the .csv files and i think i should move the images to a static repo and point to that when refering to images. - this is not uploaded to github
- found_evil.csv - output to one of the searches

## This project requires

   * Jupyter notebook
   * Python via Anaconda and/or other python packages like numpy, pandas, keras, matplotlib, sklearn. The list of anaconda default packages can be found here [Anaconda packages](https://docs.anaconda.com/anaconda/packages/py3.6_win-64/). 
    
Anaconda has python, ipython, jupyter notebook and a large number of common python packages required in Data Analysis. 

  * Get anaconda for windows [Anaconda](https://www.anaconda.com/download/))

## Jupyter 

The main body of work is in the jupyter notebook ***analyse-data.ipynb***. 


### Running a Jupyter notebook


#### Start jupyter notebook

There are two ways to start jupyter notebook. 

   1. Via the Anaconda App 
   2. Via the command line on cmder. 

I will describe the cmder approach.


Open cmder in your home directory or from a folder within the home directory. Jupyter notebook will only be able to access this folder and any sub folders. For example ...
```
C:\Users\Username\Desktop\WorkFolder\github\
```

   * Create a repo on github [GitHub Repo](https://github.com/Osheah/analyse-data)
   * Clone the repo on github by clicking the green clone or download link
    
Go to cmder and enter ... for example

```
git clone https://github.com/username/analyse-data.git

```
Open jupyter notebook using the command...

```
jupyter notebook

```
A browser should open linking the current directory in cmder to an jupyter version of windows explorer. Jupyter notebook will open at its home page http://localhost:8888/tree
Select the analyse-data.ipynb file

To use the notebook follow the tutorial [here](https://www.dataquest.io/blog/jupyter-notebook-tutorial/)
## Authors

* **Helen O'Shea** - [Osheah](https://github.com/Osheah/)

