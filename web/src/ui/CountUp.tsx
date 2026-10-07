import React from 'react';

interface CountUpProps {
  end: number;
  duration?: number;
  className?: string;
  prefix?: string;
  suffix?: string;
  separator?: string;
}

export const CountUp: React.FC<CountUpProps> = ({
  end,
  className = '',
  prefix = '',
  suffix = '',
  separator = ',',
}) => {
  // Security metrics should show their actual value as soon as data arrives.
  const formattedValue = end.toString().replace(/\B(?=(\d{3})+(?!\d))/g, separator);

  return (
    <span className={className}>
      {prefix}
      {formattedValue}
      {suffix}
    </span>
  );
};
