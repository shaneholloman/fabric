# Creating a New Branch and Replacing a Directory in Git

These instructions will guide you through the process of creating a new branch from the `main` branch of a GitHub repository, replacing a root directory with your version, and syncing those changes to the new branch.

## Prerequisites

- Git installed on your local machine
- Access to the GitHub repository
- Your version of the directory you want to replace

## Step-by-Step Instructions

1. **Clone the repository** (if you haven't already):

   ```bash
   git clone https://github.com/shaneholloman/fabric.git
   cd fabric
   ```

2. **Ensure you're on the main branch and it's up to date**:

   ```bash
   git checkout main
   git pull origin main
   ```

3. **Create and switch to the new branch**:

   ```bash
   git checkout -b standardized-patterns
   ```

4. **Remove the existing 'patterns' directory**:

   ```bash
   rm -rf patterns
   ```

5. **Copy your version of the 'patterns' directory into the repository**:

   ```bash
   cp -R /path/to/your/patterns ./
   ```

   Replace `/path/to/your/patterns` with the actual path to your version of the 'patterns' directory.

6. **Stage the changes**:

   ```bash
   git add .
   ```

7. **Commit the changes**:

   ```bash
   git commit -m "Replace patterns directory with standardized version"
   ```

8. **Push the new branch to GitHub**:

   ```bash
   git push -u origin standardized-patterns
   ```

After completing these steps, your new 'standardized-patterns' branch will be created on GitHub with your version of the 'patterns' directory.

## Notes

- Make sure you have the necessary permissions to push to the repository.
- Always double-check that you're working on the correct branch before making changes.
- It's a good practice to create a pull request on GitHub to merge your new branch into the main branch, allowing for code review and collaboration.
