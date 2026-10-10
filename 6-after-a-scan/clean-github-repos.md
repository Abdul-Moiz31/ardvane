# Cleaning infected GitHub repositories

**Do [step 2 of if-danger-found.md](if-danger-found.md#2-cut-off-access-do-this-before-cleaning-anything) first.**
If the attacker still has access, they will simply push the malware again.

## Why a normal "remove malware" commit isn't enough

The worm **amends** your latest commit and force-pushes it, often keeping the original date, on **every branch** it
can reach. If you just delete the files in a new commit:

- the malware stays in history — anyone who checks out an older commit, branch or pull request gets it;
- the next infected push from a collaborator puts it right back (this happened to the author more than once).

So: rewrite history to remove it from every branch, verify, then lock the branches.

## Safety rules while cleaning

- Never open an infected repo in an editor, never run `npm install` in it. Work on **bare** copies (no project files are written).
- Disable hooks for these commands (`-c core.hooksPath=/dev/null`, or `NUL` on Windows).
- Keep the list of old branch tips (`git for-each-ref > refs-before.txt`) so you can always go back.

## Step by step (one repository)

You need [`git-filter-repo`](https://github.com/newren/git-filter-repo) (`brew install git-filter-repo` / `pip install git-filter-repo`).

```bash
# 1. Bare copy of everything (no files are written, nothing can run)
git -c core.hooksPath=/dev/null clone --mirror https://github.com/<owner>/<repo>.git repo.git
cd repo.git
git for-each-ref --format='%(objectname) %(refname)' refs/heads refs/tags > ../refs-before.txt

# 2. See what's infected (prints file names, reads only)
git rev-list --objects --all | grep -E 'fa-solid-[0-9]+\.(woff2?|eot|llf)|/api\.js$|\.vscode/(tasks|settings)\.json$|temp_auto_push|config\.bat'

# 3. Remove files that are 100% malware from ALL history (adjust the list to what you found)
git filter-repo --force --invert-paths \
  --path-glob '*fonts/fa-solid-500.woff2' --path-glob '*fonts/fa-solid-900.eot' --path-glob '*.llf' \
  --path-glob 'temp_auto_push.bat' --path-glob 'temp_interactive_push.bat'
```

For files that are **partly** yours (config files with the payload appended after spaces, `.vscode/tasks.json`
you also use, `.gitignore`), don't delete them — strip only the injected part. `git filter-repo --blob-callback`
can cut each blob at the long whitespace run that precedes the payload, or you can restore the last clean version
of those files. Check the result:

```bash
# 4. Verify: export the newest version of every branch to a temp folder and scan it
for b in $(git for-each-ref --format='%(refname:short)' refs/heads); do
  d=$(mktemp -d); git --work-tree="$d" checkout -f "$b" -- . 2>/dev/null; checkrepo "$d" || echo "STILL INFECTED: $b"; rm -rf "$d"
done

# 5. Push the cleaned branches back (only after step 4 is clean everywhere)
git remote add origin https://github.com/<owner>/<repo>.git 2>/dev/null
git push --force origin 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'
```

`git filter-repo` removes the `origin` remote on purpose, which is why step 5 adds it back.

## Many repositories?

The author had ~150 infected repositories (own repos, forks, organization repos). What worked:

- **Forks you don't actively use: delete them.** Deleting is instant and leaves nothing to clean. You can re-fork later.
- **Forks with open pull requests to other projects: clean them, or close the pull requests.** Their PR branches carry the
  malware to the upstream maintainers.
- **Your own repos: script steps 1–5 in a loop**, and before force-pushing compare every branch's files with the GitHub
  version to make sure **only malware** changed — never your real code.
- **Organization / other people's repos: tell the owners.** Don't force-push to repos you don't own without agreement.

## After cleaning

- [ ] **Protect branches** (repo Settings → Rules → Rulesets): block force pushes on all branches, block deletion of the
      default branch, require signed commits. On the free plan this works for public repos; private repos need GitHub Pro.
- [ ] **Re-clone** your local copies from GitHub. Old local copies still contain the infected history.
- [ ] **Pull-request refs can't be rewritten.** GitHub keeps a read-only copy of every pull request (`refs/pull/*`) that may
      still point at infected commits. Normal clones don't download them, but to remove them completely, contact
      GitHub Support (support.github.com → Repositories) and ask them to purge cached commits and PR refs for the listed repos.
- [ ] Check deploy keys, webhooks, collaborators and GitHub Actions workflows in each repo for anything you didn't add.
