FILES=data/MinGW/*
for f in $FILES
do
  7za a -t7z "data/MinGW/$(basename $f).7z" $f -mx9 -mhe
done
